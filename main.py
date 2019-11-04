import intel.et
from suricata import Suricata
import datetime, functools, json, logging, os, pprint, queue, signal, smtplib, sys, threading, time

class Downloader(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Downloader'

        self.config = config

        self.stop = False

    def run(self):
        modules = [intel.et]

        lastupdate = {}
        installed = False
        for module in modules:
            local = None
            try:
                m = module.__name__.split('.', maxsplit=1)[1]
                local = datetime.datetime.fromtimestamp(os.stat('/etc/suricata/rules/osint-suricata-{}.rules'.format(m)).st_mtime)
            except:
                pass
                
            remote = module.latest(self.config)
            assert remote is not None

            lastupdate[module.__name__] = local if local else datetime.datetime.fromtimestamp(0)

            if local is None or local < remote:
                logger.info('updating %s ruleset', module.__name__)
                rv = module.install(self.config, self)
                if rv is None or self.stop:
                    return

                lastupdate[module.__name__] = rv
                installed = True

        if installed:
            with Suricata() as suri:
                assert suri.reloadrules()

        lastcheck = time.time()
        while not self.stop:
            time.sleep(1)

            if time.time() - lastcheck >= 3600:
                installed = False
                for module in modules:
                    remote = module.latest(self.config)
                    assert remote is not None

                    if lastupdate[module.__name__] < remote:
                        logger.info('updating %s ruleset', module.__name__)

                        rv = module.install(self.config, self)
                        if rv is None or self.stop:
                            return

                        lastupdate[module.__name__] = rv
                        installed = True

                if installed:
                    with Suricata() as suri:
                        assert suri.reloadrules()

class Notifier(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Notifier'

        self.config = config

        self.stop = False

        self.alerts = queue.Queue()

    def run(self):
        smtp = smtplib.SMTP(self.config['smtpserver'])

        alerts_total = []

        while not self.stop:
            if not self.alerts.empty():
                alert = self.alerts.get()

                body = 'Subject: {}\r\nFrom: osint-suricata@docker\r\n\r\n'.format(alert['alert']['signature']) + pprint.pformat(alert)

                alerts_total += [time.time()]
                alerts_total = list(filter(lambda t: time.time() - t < 24*60*60, alerts_total))
                if len(alerts_total) > 100:
                    logging.error('too many alerts within 24 hours, aborting')
                    body += '\ntoo many alerts within 24 hours, aborting\n'
                    self.stop = True

                once = True
                success = False
                while once:
                    try:
                        smtp.sendmail(self.config['mailtofrom'], self.config['mailtofrom'], body)
                        logging.info('alert mail for %s sent', alert['alert']['signature'])
                        success = True
                        break

                    # SMTP command timeout, broken pipe, etc
                    except smtplib.SMTPException:
                        once = False
                        smtp = smtplib.SMTP(self.config['smtpserver'])

                assert success
                self.alerts.task_done()

            else:
                time.sleep(1)

        smtp.quit()

class Parser(threading.Thread):
    def __init__(self, config, notifier):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Parser'

        self.config = config
        self.notifier = notifier

        self.stop = False

    def run(self):
        evefile = open('/var/log/suricata/eve.json', 'r', encoding='utf-8')
        evefile.seek(0, os.SEEK_END)

        stats = {}
        since = time.time()

        errors_total = []

        while not self.stop:
            line = evefile.readline()
            if not line:
                # Test for log file rotation by comparing the modification times of the file path and the open file
                d1 = datetime.datetime.fromtimestamp(os.stat('/var/log/suricata/eve.json').st_mtime)
                d2 = datetime.datetime.fromtimestamp(os.stat(evefile.fileno()).st_mtime)
                if d1 > d2:
                    logging.info('detected log file rotation, reopening file')
                    evefile = open('/var/log/suricata/eve.json', 'r', encoding='utf-8')
                    evefile.seek(0, os.SEEK_END)
                else:
                    time.sleep(0.25)
                continue

            stats['lines'] = stats.get('lines', 0) + 1

            try:
                record = json.loads(line)
            except:
                logging.exception('line = %r', line)
                stats['errors'] = stats.get('errors', 0) + 1

                errors_total += [time.time()]
                errors_total = list(filter(lambda t: time.time() - t < 24*60*60, errors_total))
                if len(errors_total) > 10:
                    logging.error('too many errors within 24 hours, aborting')
                    break
                continue

            assert 'event_type' in record
            stats[record['event_type']] = stats.get(record['event_type'], 0) + 1

            if record['event_type'] == 'alert':
                logging.debug('\n' + pprint.pformat(record))
                notifier.alerts.put(record)

            if time.time() - since >= 600:
                logging.info('stats = %r', stats)
                stats = {}
                since = time.time()

            # TODO Periodically report metrics / stats
            #      See dump-counters and iface-stat suricata socket commands
            #      Alternatively can parse suricata stats records
            #      Specifically monitor suricata dropped packet counts

        evefile.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(name)s:%(threadName)s:%(message)s')

    with open('config.json') as f:
        config = json.load(f)

    with Suricata() as suri:
        v = suri.version()
        logging.info('suricata version = %s', v)
        config.update({'version': v})

        enabled = False
        for i in range(10):
            if suri.confget('outputs.{}.eve-log.enabled'.format(i)) == 'yes':
                enabled = True
                break
        assert enabled

    downloader = Downloader(config)
    notifier = Notifier(config)
    parser = Parser(config, notifier)

    threads = [downloader, notifier, parser]
    for t in threads:
        t.start()

    def stop(signum, frame):
        logging.info('received signal %d', signum)
        for t in threads:
            t.stop = True
            t.join()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while True:
        if not functools.reduce(lambda a,b: a and b, [t.is_alive() for t in threads]):
            stopped = functools.reduce(lambda a,b: a and b, [t.stop for t in threads])

            for t in threads:
                if t.is_alive():
                    t.stop = True
                    t.join()

            if not stopped:
                body = 'Subject: ungraceful shutdown\r\nFrom: osint-suricata@docker\r\n\r\nungraceful shutdown, check docker container logs'
                smtp = smtplib.SMTP(config['smtpserver'])
                smtp.sendmail(config['mailtofrom'], config['mailtofrom'], body)
                smtp.quit()

            break

        time.sleep(1)
