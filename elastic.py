import dateparser
import requests

import collections
import datetime
import json
import logging
import queue
import signal
import smtplib
import socket
import threading
import time


alert_queue = queue.Queue()


class ListenerWorker(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = f'ListenerWorker{sock.fileno()}'

        self.__sock = sock
        self.__stop = False


    def run(self):
        self.__sock.settimeout(1)

        buf = b''

        stats = collections.defaultdict(int)
        last = time.time()

        while not self.__stop:
            if len(stats) > 0 and time.time() - last >= 3600:
                logging.info('stats: %s', ', '.join(['%s = %d' % (k, stats[k]) for k in sorted(stats.keys())]))
                stats = collections.defaultdict(int)
                last = time.time()

            try:
                b = self.__sock.recv(1024)
            except socket.timeout as e:
                continue

            # Socket closed by peer
            if b == b'':
                break
            logging.debug('b = %r', b)

            buf += b
            lines = buf.splitlines(keepends=True)
            buf = b''

            # Handle an incomplete last line
            if lines[-1][-1] != ord('\n'):
                buf = lines[-1]
                lines = lines[:-1]
                stats['incomplete'] += 1

            for line in lines:
                logging.info('received line: %r', line)
                stats['lines-read'] += 1

                try:
                    record = json.loads(line)
                except Exception as e:
                    logging.error('error processing line = %r: %s', line, e)
                    stats['bad-json'] += 1
                    continue

                if record.get('event_type') != 'alert':
                    stats['non-alerts'] += 1
                    continue

                alert_queue.put(line)

        if buf != b'':
            logging.warning('unused buffer: %r', buf)

        self.__sock.close()


    def stop(self):
        self.__stop = True


class Listener(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Listener'

        self.__stop = False
        self.__workers = []


    def run(self):
        self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__server.bind(('127.0.0.1', 7834))
        self.__server.listen()
        self.__server.settimeout(1)

        last = time.time()

        while not self.__stop:
            try:
                client, info = self.__server.accept()
            except socket.timeout:
                continue

            # Clean out dead worker threads periodically
            if time.time() - last > 100:
                self.__workers = [w for w in self.__workers if w.is_alive()]
                last = time.time()

            logging.info('received a connection from %s:%d', info[0], info[1])
            worker = ListenerWorker(client); worker.start()
            self.__workers += [worker]

        self.__server.close()


    def stop(self):
        self.__stop = True
        for w in self.__workers:
            if w.is_alive():
                w.stop(); w.join()


class Notifier(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Notifier'

        self.__stop = False


    def run(self):
        # Get the Kibana index pattern guid (used later when building Kibana urls)

        index_pattern_guid = None

        resp = requests.get('http://127.0.0.1:5601/api/saved_objects/_find',
                             params = {'type':'index-pattern', 'search':'suricata-*'},
                            timeout = 100)
        resp.raise_for_status()
        for pattern in resp.json()['saved_objects']:
            guid = pattern.get('id')
            if guid is None:
                continue
            if pattern.get('attributes', {}).get('title') == 'suricata-*':
                index_pattern_guid = guid
                break

        if index_pattern_guid is None:
            logging.error('unable to determine index pattern guid')
            return
        logging.debug('index_pattern_guid = %s', index_pattern_guid)

        def mail_alerts(alert_lines):
            body = 'Subject: suricata alerts\r\nFrom: frosty@localhost\r\n'

            if False:
                body += '\n'.join([json.dumps(a.decode(), indent=4) for a in alert_lines])
            else:
                def get(alert, keys):
                    curval = alert
                    for key in keys:
                        if not isinstance(curval, dict) or key not in curval:
                            logging.warning('alert missing %s: %r', '.'.join(keys), alert)
                            return None
                        curval = curval[key]
                    return curval

                def url(flowid, flowstart, timestamp):
                    url = 'http://127.0.0.1:5601/app/discover#/?' + \
                          '_g=(filters:!(),refreshInterval:(pause:!t,value:0),'

                    start = (dateparser.parse(flowstart) - datetime.timedelta(minutes=5)).isoformat()
                    end   = (dateparser.parse(timestamp) + datetime.timedelta(minutes=5)).isoformat()

                    url += f"time:(from:'{start}',to:'{end}'))&" + \
                           '_a=(columns:!(event_type,src_ip,src_port,dest_ip,dest_port,proto,app_proto),' + \
                           f"filters:!(),index:'{index_pattern_guid}',interval:auto,sort:!()," + \
                           f"query:(language:kuery,query:'flow_id:{flowid}'))"

                    return url

                valid = False
                for alert_line in alert_lines:
                    try:
                        alert = json.loads(alert_line)
                    except Exception as e:
                        logging.error('error processing line = %r: %s', alert_line, e)
                        continue

                    signature = get(alert, ['alert', 'signature'])
                    flowid    = get(alert, ['flow_id'])
                    flowstart = get(alert, ['flow', 'start'])
                    timestamp = get(alert, ['timestamp'])
                    if any([x is None for x in [signature, flowid, flowstart, timestamp]]):
                        continue

                    body += f'{signature}\n{url(flowid, flowstart, timestamp)}\n\n'
                    valid = True

                if not valid:
                    return

            smtp = smtplib.SMTP('127.0.0.1')
            smtp.sendmail('frosty@localhost', 'root@localhost', body)
            smtp.quit()

            logging.info('sent mail with %d alerts', len(alerts))

        last = time.time()

        while not self.__stop:
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


    def stop(self):
        self.__stop = True


def main_elastic():
    listener = Listener(); listener.start()
    notifier = Notifier(); notifier.start()

    # Gracefully stop on terminating signal

    def stop(signum, frame):
        logging.info('received signal %s', signal.Signals(signum).name)
        listener.stop(); listener.join()
        notifier.stop(); alert_queue.join(); notifier.join()

    for s in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(s, stop)

    # Gracefully stop if any individual thread stops

    while True:
        if not listener.is_alive():
            notifier.stop(); alert_queue.join(); notifier.join()
            break

        if not notifier.is_alive():
            listener.stop(); listener.join()
            while not alert_queue.empty():
                alert = alert_queue.get()
                alert_queue.task_done()
                logging.error('unhandled alert: %s', alert)
            break

        time.sleep(1)
