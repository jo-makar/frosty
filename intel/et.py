import pytz, requests, tzlocal
import datetime, logging, os, os.path, subprocess, tempfile

def _url(config):
    if 'etpro_oink' in config:
        return 'https://rules.emergingthreatspro.com/{}/suricata-{}/etpro.rules.tar.gz'.format(config['etpro_oink'], config['version'])
    else:
        return 'https://rules.emergingthreats.net/open/suricata-{}/emerging.rules.tar.gz'.format(config['version'])

def _download(url, thread):
    path = os.path.join('/tmp', url.split('/')[-1])

    try:
        resp = requests.get(url, stream=True, timeout=100)
        with open(path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=None):
                if thread.stop:
                    return None, None

                f.write(chunk)
                f.flush()
    except:
        logging.exception('url = %s', url)
        return None, None

    return path, _lastmod(resp.headers['Last-Modified'])

def _lastmod(header):
    try:
        rv = datetime.datetime.strptime(header, '%a, %d %b %Y %H:%M:%S %Z')
    except:
        logging.exception('unable to determine when last modified')
        return None

    if header.split()[-1] not in ['GMT', 'UTC']:
        logging.error('last-modified not in utc')
        return None

    return pytz.utc.localize(rv).astimezone(tzlocal.get_localzone())

def latest(config):
    resp = requests.head(_url(config), timeout=100)
    if not resp.ok:
        return None

    return _lastmod(resp.headers['Last-Modified'])

def install(config, thread):
    url = _url(config)
    logging.info('downloading %s', url)
    tarball, lastmod = _download(url, thread)
    if tarball is None or lastmod is None:
        return None
    logging.info('%s downloaded successfully', tarball)

    with tempfile.TemporaryDirectory() as tmpdir:
        if subprocess.call(['tar', 'xf', tarball, '-C', tmpdir]) != 0:
            logging.error('tar returned a non-zero exit code')
            return None

        if not os.path.join(tmpdir, 'rules'):
            logging.error('rules dir not found in tarball')
            return None

        rules = []
        for entry in os.listdir(os.path.join(tmpdir, 'rules')):
            path = os.path.join(tmpdir, 'rules', entry)
            if os.path.isfile(path) and path.endswith('.rules'):
                rules += [path]
            
        logging.info('%u et rules files found', len(rules))

        with open('/etc/suricata/rules/osint-suricata-et.rules', 'w', encoding='utf-8') as masterfile:

            alerts = 0
            blacklisted = 0

            for path in rules:
                with open(path, 'r', encoding='utf-8') as rulefile:
                    blacklist = config.get('et-blacklist', {}).get(os.path.basename(path), [])

                    for line in rulefile:
                        reject = False

                        if line.startswith('alert '):
                            alerts += 1

                            for entry in blacklist:
                                if entry in line: # substring matching
                                    blacklisted += 1
                                    reject = True
                                    break

                        if not reject:
                            masterfile.write(line)

                    masterfile.write('\n\n\n')

            logging.info('with %u rules in total and %u blacklisted', alerts, blacklisted)

    os.unlink(tarball)

    return lastmod
