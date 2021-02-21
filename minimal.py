import inotify.adapters

import collections
import json
import logging
import os
import queue
import signal
import smtplib
import sys
import threading
import time


alert_queue = queue.Queue()


class Parser(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Parser'

        self.stop = False


    def run(self):
        evefile = open('/var/log/suricata/eve.json', 'r', encoding='utf-8')
        evefile.seek(0, os.SEEK_END)
        inotifier = inotify.adapters.Inotify(paths=[evefile.name])

        stats = collections.defaultdict(int)
        last = time.time()

        while not self.stop:
            reopen = False
            for event in inotifier.event_gen(timeout_s=1):
                if event is None:
                    continue
                logging.debug('event = %r', event)

                _, types, _, _ = event
                for t in types:

                    # If the file is modified read lines until eof
                    if t == 'IN_MODIFY':
                        while not self.stop:
                            pos = evefile.tell()
                            line = evefile.readline()
                            if line == '':
                                break

                            # Handle incomplete lines
                            if isinstance(line, bytes) or not line.endswith('\n'):
                                evefile.seek(pos)
                                time.sleep(0.1)
                                stats['incomplete'] += 1
                                continue

                            logging.debug('line = %r', line)
                            stats['lines-read'] += 1

                            try:
                                record = json.loads(line)
                            except Exception as e:
                                logging.error('error processing line = %r: %s', line, e)
                                stats['bad-json'] += 1
                                break

                            if record.get('event_type') == 'alert':
                                alert_queue.put(record)
                                stats['alerts'] += 1

                            break

                    elif t == 'IN_CLOSE_WRITE':
                        reopen = True

            if reopen:
                logging.info('detected file write (eg log rotation), reopening file')
                evefile.close()
                evefile = open('/var/log/suricata/eve.json', 'r', encoding='utf-8')
                stats['reopens'] += 1

            if len(stats) > 0 and time.time() - last >= 3600:
                logging.info('stats: %s', ', '.join(['%s = %d' % (k, stats[k]) for k in sorted(stats.keys())]))
                stats = collections.defaultdict(int)
                last = time.time()

        evefile.close()


class Notifier(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Notifier'

        self.stop = False


    def run(self):
        def mail_alerts(alerts):
            body = 'Subject: suricata alerts\r\nFrom: frosty@localhost\r\n'
            body += '\n'.join([json.dumps(a, indent=4) for a in alerts])

            smtp = smtplib.SMTP('127.0.0.1')
            smtp.sendmail('frosty@localhost', 'root@localhost', body)
            smtp.quit()

            logging.info('sent mail with %d alerts', len(alerts))

        last = time.time()

        while not self.stop:
            if not alert_queue.empty() and time.time() - last >= 300:
                alerts = []
                while not alert_queue.empty():
                    alerts += [alert_queue.get()]
                    alert_queue.task_done()

                mail_alerts(alerts)
                last = time.time()

            time.sleep(1)

        if not alert_queue.empty():
            alerts = []
            while not alert_queue.empty():
                alerts += [alert_queue.get()]
                alert_queue.task_done()

            mail_alerts(alerts)


def main_minimal():
    parser = Parser(); parser.start()
    notifier = Notifier(); notifier.start()

    # Gracefully stop on terminating signal

    def stop(signum, frame):
        logging.info('received signal %s', signal.Signals(signum).name)
        parser.stop = True; parser.join()
        notifier.stop = True; alert_queue.join(); notifier.join()

    for s in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(s, stop)

    # Gracefully stop if any individual thread stops

    while True:
        if not parser.is_alive():
            notifier.stop = True; alert_queue.join(); notifier.join()
            break

        if not notifier.is_alive():
            parser.stop = True; parser.join()
            while not alert_queue.empty():
                alert = alert_queue.get()
                alert_queue.task_done()
                logging.error('unhandled alert: %s', alert)
            break

        time.sleep(1)
