import requests
import datetime, logging, os, os.path, subprocess, tempfile


def _download(url, thread):
    '''Download a file in chunks to allow interruption'''

    path = os.path.join('/tmp', url.split('/')[-1])

    try:
        resp = requests.get(url, stream=True)
        with open(path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=None):
                if thread.stop:
                    return None

                f.write(chunk)
                f.flush()
    except:
        logging.exception('url = %s', url)
        return None

    return path


def _url(config):
    if 'etpro_oink' in config:
        return 'https://rules.emergingthreatspro.com/' + \
                   '%s/suricata-%s/etpro.rules.tar.gz' % \
                       (config['etpro_oink'], config['version'])
    else:
        return 'https://rules.emergingthreats.net/' + \
                   'open/suricata-%s/emerging.rules.tar.gz' % \
                       config['version']


def install(config, thread):
    url = _url(config)
    logging.info('downloading %s', url)
    tarball = _download(url, thread)
    if not tarball:
        return None
    rv = datetime.datetime.utcnow()
    logging.info('%s downloaded successfully', tarball)

    # The tarball will be composed of a rules dir with *.rules files
    # (in addition to other text and yaml files)

    with tempfile.TemporaryDirectory() as tmpdir:
        if subprocess.call(['tar', 'xzf', tarball, '-C', tmpdir]) != 0:
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
            
        logging.info('%u ET rules files found', len(rules))

        with open('/etc/suricata/rules/osint-suricata-et.rules',
                  'w', encoding='utf-8') as masterfile:

            alerts = 0
            blacklisted = 0

            for path in rules:
                with open(path, 'r', encoding='utf-8') as rulefile:
                    blacklist = config.get('et-blacklist', {}) \
                                      .get(os.path.basename(path), [])

                    for line in rulefile:
                        reject = False

                        if line.startswith('alert '):
                            alerts += 1

                            for entry in blacklist:
                                # Substring matching
                                if entry in line:
                                    blacklisted += 1
                                    reject = True
                                    break

                        if not reject:
                            masterfile.write(line)

                    masterfile.write('\n\n\n')

            logging.info('with %u rules in total and %u blacklisted',
                         alerts, blacklisted)

    #os.unlink(tarball)

    return rv


def latest(config):
    resp = requests.head(_url(config))
    
    if not resp.ok:
        return None
    try:
        # Eg: 'Fri, 30 Mar 2018 21:20:31 GMT'
        rv = datetime.datetime.strptime(resp.headers['Last-Modified'],
                                        '%a, %d %b %Y %H:%M:%S %Z')
    except:
        logging.exception('unable to determine when last modified')
        return None

    if resp.headers['Last-Modified'].split()[-1] not in ['GMT', 'UTC']:
        logging.error('last-modified not in utc')
        return None

    return rv

# vim: set textwidth=80
