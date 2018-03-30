from suricata import *
import json, logging


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')

    with open('config.json') as f:
        config = json.load(f)

    ver = suricata_version()
    if not ver:
        logging.error('unable to communicate with suricata')
        return
    logging.info('suricata version = %s', ver)

    # TODO Would be good to verify "conf-get outputs.eve-log.enabled"
    #      but this does not seem to be supported by the interface currently

    # FIXME STOPPED
    # Define two threads, one downloads intel (separate class for each, start with et)
    #                     the other processes /var/log/suricata/eve.json for alerts to mail
    # ET pro url: https://rules.emergingthreatspro.com/oink/suricata-3.2.1/etpro.rules.tar.gz

# vim: set textwidth=80
