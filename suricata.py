# Interface to the Suricata command socket (ie /var/run/suricata-command.socket).
# Ensure that the unix-command option is enabled in the Suricata configuration.
# Ref: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Unix_Socket#Protocol

import json, logging, re, socket

_INBUFLEN = 4096

def _connect():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/var/run/suricata-command.socket')

    outbuf = b'{"version":"0.1"}'
    sock.sendall(outbuf)
    logging.debug('>>> %r', outbuf)
    inbuf = sock.recv(_INBUFLEN)
    logging.debug('<<< %r', inbuf)

    try:
        resp = json.loads(inbuf.decode('utf-8'))
    except:
        logging.exception('failed to parse response')
        sock.close()
        return None

    if resp.get('return') != 'OK':
        logging.error('unexpected response')
        sock.close()
        return None

    return sock


def _command(sock, cmd, args={}, full=False):
    outjson = {'command': cmd}
    if args:
        outjson['arguments'] = args

    outbuf = bytearray(json.dumps(outjson), 'utf-8')
    sock.sendall(outbuf)
    logging.debug('>>> %r', outbuf)
    inbuf = sock.recv(_INBUFLEN)
    logging.debug('<<< %r', inbuf)

    try:
        resp = json.loads(inbuf.decode('utf-8'))
    except:
        logging.exception('failed to parse response')
        sock.close()
        return None

    if full:
        return resp
    else:
        if resp.get('return') != 'OK':
            logging.error('unexpected response')
            sock.close()
            return None

        if 'message' not in resp:
            logging.error('unexpected response')
            sock.close()
            return None

        return resp['message']


def suricata_version():
    sock = _connect()
    if not sock:
        return None

    resp = _command(sock, 'version')
    if not resp:
        return None

    sock.close()

    mat = re.match('^\d+\.\d+\.\d+', resp)
    if not mat:
        logging.error('unexpected version format: %s', resp)
        return None

    return mat.group(0)
