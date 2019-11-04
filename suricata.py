# Ref: https://suricata.readthedocs.io/en/suricata-4.1.2/unix-socket.html
#      https://github.com/OISF/suricata/blob/master/python/suricata/sc/specs.py

import json, logging, socket, time

class Suricata:
    def __init__(self):
        pass

    def __enter__(self):
        self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.__sock.connect('/var/run/suricata-command.socket')
        self.__sock.settimeout(600)

        outbuf = b'{"version":"0.1"}'
        self.__sock.sendall(outbuf)
        logging.debug('>>> %r', outbuf)
        inbuf = self.__sock.recv(1024)
        logging.debug('<<< %r', inbuf)

        resp = json.loads(inbuf.decode('utf-8'))
        assert resp.get('return') == 'OK'

        return self

    def __exit__(self, exctype, excval, traceback):
        if exctype is None:
            self.__sock.close()

    def __command(self, cmd, args={}, full=False):
        outjson = {'command': cmd}
        if args:
            outjson['arguments'] = args

        outbuf = bytearray(json.dumps(outjson), 'utf-8')
        self.__sock.sendall(outbuf)
        logging.debug('>>> %r', outbuf)

        inbuf = self.__sock.recv(4096)
        logging.debug('<<< %r', inbuf)

        resp = json.loads(inbuf.decode('utf-8'))

        if full:
            return resp
        else:
            assert resp.get('return') == 'OK'
            assert 'message' in resp
            return resp['message']

    def version(self):
        return self.__command('version').split()[0]

    def confget(self, name):
        resp = self.__command('conf-get', args={'variable':name}, full=True)

        if resp.get('return') == 'NOK': # not ok
            return None

        assert resp.get('return') == 'OK'
        assert 'message' in resp
        return resp['message']

    def reloadrules(self):
        try:
            s = time.time()
            self.__command('ruleset-reload-rules')
        except socket.timeout:
            logging.error('socket timeout')
            return False

        logging.info('rules reloaded in %.1f secs', time.time() - s)
        stats = self.__command('ruleset-stats')[0]
        logging.info('%u rules loaded, %u rules failed', stats['rules_loaded'], stats['rules_failed'])
        if stats['rules_failed'] > 0:
            logging.info('failed rules: %r', self.__command('ruleset-failed-rules')[0])

        return True
