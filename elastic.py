import collections
import json
import logging
import queue
import signal
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

                # FIXME alert_queue.put(line)

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
        while not self.__stop:
            time.sleep(1) # FIXME STOPPED


    def stop(self):
        self.__stop = True


class Cleaner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = False
        self.name = 'Cleaner'

        self.__stop = False


    def run(self):
        # FIXME delete records older than 90 days from elasticsearch
        while not self.__stop:
            time.sleep(1) # FIXME


    def stop(self):
        self.__stop = True


def main_elastic():
    listener = Listener(); listener.start()
    notifier = Notifier(); notifier.start()
    cleaner = Cleaner(); cleaner.start()

    # Gracefully stop on terminating signal[o

    def stop(signum, frame):
        logging.info('received signal %s', signal.Signals(signum).name)
        listener.stop(); listener.join()
        notifier.stop(); alert_queue.join(); notifier.join()
        cleaner.stop(); cleaner.join()

    for s in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(s, stop)

    # Gracefully stop if any individual thread stops

    while True:
        if not listener.is_alive():
            notifier.stop(); alert_queue.join(); notifier.join()
            cleaner.stop(); cleaner.join()
            break

        if not notifier.is_alive():
            listener.stop(); listener.join()
            while not alert_queue.empty():
                alert = alert_queue.get()
                alert_queue.task_done()
                logging.error('unhandled alert: %s', alert)
            cleaner.stop(); cleaner.join()
            break

        if not cleaner.is_alive():
            listener.stop(); listener.join()
            notifier.stop(); alert_queue.join(); notifier.join()

        time.sleep(1)
