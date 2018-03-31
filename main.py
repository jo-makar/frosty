import intel.et
from suricata import *
import json, logging, os, pprint, queue, signal, smtplib, sys, threading, time


class EventParser(threading.Thread):
    def __init__(self, config, notifier):
        threading.Thread.__init__(self, daemon=False)

        self.stop = False
        self.config = config


    def run(self):
        evefile = open('/var/log/suricata/eve.json', 'r')
        evefile.seek(0, os.SEEK_END)

        since = time.time()
        count = 0

        # FIXME Does this survive log rotation? Verify at 6:25
        while not self.stop:
            line = evefile.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                record = json.loads(line)
            except:
                logging.exception('line = %r', line)
                # TODO Consider sending an email with the exception
                self.stop = True

            if record.get('event_type') == 'alert':
                logging.debug('\n' + pprint.pformat(record))
                notifier.alerts.put(record)
                count += 1

            if time.time() - since >= 60:
                if count > 0:
                    logging.info('%u alerts generated', count)
                since = time.time()
                count = 0

            # TODO Consider reporting metrics or accumulated stats (daily?).
            #      Perhaps to start a report on flows (top most contacted IPs).

        evefile.close()


class Notifier(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self, daemon=False)

        self.stop = False
        self.config = config

        self.alerts = queue.Queue()
        self.others = queue.Queue()


    def run(self):
        smtp = smtplib.SMTP(self.config['smtpserver'])

        while not self.stop:
            if not self.alerts.empty():
                alerts = [self.alerts.get()]
                while not self.alerts.empty() and len(alerts) < 10:
                    alerts += [self.alerts.get()]

                smtp.sendmail(self.config['mailtofrom'],
                              self.config['mailtofrom'],
                              '\r\n' + '\n\n'.join(map(lambda a: pprint.pformat(a),
                                                       alerts)))

                for i in range(len(alerts)):
                    self.alerts.task_done()

            elif not self.others.empty():
                smtp.sendmail(self.config['mailtofrom'],
                              self.config['mailtofrom'],
                              self.others.get())
                self.others.task_done()

            else:
                time.sleep(1)

        smtp.quit()


class Downloader(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self, daemon=False)

        self.stop = False
        self.config = config


    def run(self):
        last = {}

        l = intel.et.install(config, self)
        if not l:
            self.stop = True
        last['et'] = l

        while not self.stop:
            # FIXME STOPPED
            time.sleep(1)


if __name__ == '__main__':
    def stop(signum, frame):
        logging.info('received signal %d', signum)

        for t in threads:
            t.stop = True
            t.join()


    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s:%(levelname)s:%(name)s:%(threadName)s:%(message)s')

    with open('config.json') as f:
        config = json.load(f)

    ver = suricata_version()
    if not ver:
        logging.error('unable to communicate with suricata')
        sys.exit(1)
    logging.info('suricata version = %s', ver)
    config.update({'version': ver})

    # TODO Would be good to verify "conf-get outputs.eve-log.enabled"
    #      but this does not seem to be supported by the interface currently

    notifier = Notifier(config)
    parser = EventParser(config, notifier)
    downloader = Downloader(config)

    threads = [notifier, parser, downloader]
    for t in threads:
        t.start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while True:
        stopall = False
        for t in threads:
            if not t.is_alive():
                stopall = True
                break

        if stopall:
            for t in threads:
                if t.is_alive():
                    t.stop = True
                    t.join()
            break

        time.sleep(1)

# vim: set textwidth=80
