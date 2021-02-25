#!/usr/bin/env python3

import elasticsearch
import gmail
import kibana

import collections
import datetime
import io
import logging


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(filename)s:%(lineno)d:%(message)s')
    #logging.getLogger().disabled = True

    #
    # Gather the data
    #

    start = datetime.datetime.now() - datetime.timedelta(days=7)
    query = {
        'size': 5000,
        'query': {
            'bool': {
                'must': [
                    {
                        'match': {
                            'event_type': 'http'
                        }
                    },
                    {
                        'range': {
                            'timestamp': {
                                'gte': start.isoformat(),
                                'lte': 'now',
                                'time_zone': '-05:00'
                            }
                        }
                    }
                ]
            }
        },
        'sort': [
            { 'timestamp': 'asc' },
            { '_id': 'asc' }
        ]
    }

    http_entries = {}
    for record in elasticsearch.search(query, start):
        flow_id = record['_source']['flow_id']
        if 'hostname' not in record['_source']['http']:
            logging.warning('http record with http.hostname missing (flow_id = %d)', flow_id) 
            continue
        hostname = record['_source']['http']['hostname']

        if flow_id in http_entries:
            assert http_entries[flow_id]['hostname'] == hostname
        else:
            flow_record = elasticsearch.flow(flow_id, start)
            if flow_record is None:
                logging.warning('flow record with flow_id = %d missing', flow_id)
                bandwidth = 0
            else:
                bandwidth = flow_record['_source']['flow']['bytes_toclient'] + \
                            flow_record['_source']['flow']['bytes_toserver']

            http_entries[flow_id] = {'hostname':hostname, 'bandwidth':bandwidth}

    query['query']['bool']['must'][0]['match']['event_type'] = 'tls'
    tls_entries = {}
    for record in elasticsearch.search(query, start):
        flow_id = record['_source']['flow_id']
        hostname = record['_source']['tls']['sni']

        if flow_id in tls_entries:
            assert tls_entries[flow_id]['hostname'] == hostname
        else:
            flow_record = elasticsearch.flow(flow_id, start)
            if flow_record is None:
                logging.warning('flow record with flow_id = %d missing', flow_id)
                bandwidth = 0
            else:
                bandwidth = flow_record['_source']['flow']['bytes_toclient'] + \
                            flow_record['_source']['flow']['bytes_toserver']

            tls_entries[flow_id] = {'hostname':hostname, 'bandwidth':bandwidth}

    #
    # Organize the data
    #

    http_entries_by_count = collections.defaultdict(int)
    for entry in http_entries.values():
        http_entries_by_count[entry['hostname']] += 1

    http_entries_by_bandwidth = collections.defaultdict(int)
    for entry in http_entries.values():
        http_entries_by_bandwidth[entry['hostname']] += entry['bandwidth']

    tls_entries_by_count = collections.defaultdict(int)
    for entry in tls_entries.values():
        tls_entries_by_count[entry['hostname']] += 1

    tls_entries_by_bandwidth = collections.defaultdict(int)
    for entry in tls_entries.values():
        tls_entries_by_bandwidth[entry['hostname']] += entry['bandwidth']

    #
    # Display the data
    #

    body = io.StringIO()

    body.write('<html><body>')

    # Gmail strips out specific css fields, defining columns using tables and whitelisted properties:
    # https://julie.io/writing/gmail-first-strategy-for-responsive-emails/

    prefix = '<table width="100%" align="left" style="width:100%; max-width:200px"><tr><td style="padding-left:10px; padding-right:10px">'
    postfix = '</td></tr></table>'

    body.write(f'{prefix}<h1>http connections</h1><ul>')
    for entry in sorted(http_entries_by_count.items(), key=lambda i:i[1], reverse=True):
        url = kibana.url(f'http.hostname:{entry[0]}', start)
        body.write(f'<li><a href="{url}">{entry[0]}</a> {entry[1]}</li>')
    body.write(f'</ul>{postfix}')

    def filesize(n: int) -> str:
        if n < 1024:
            return f'{n}B'
        elif n < 1024**2:
            return f'{n / float(1024):.2f}KB'
        elif n < 1024**3:
            return f'{n / float(1024**2):.2f}MB'
        elif n < 1024**4:
            return f'{n / float(1024**3):.2f}GB'
        else:
            return f'{n / float(1024**4):.2f}TB'

    body.write(f'{prefix}<h1>http bandwidth</h1><ul>')
    for entry in sorted(http_entries_by_bandwidth.items(), key=lambda i:i[1], reverse=True):
        url = kibana.url(f'http.hostname:{entry[0]}', start)
        body.write(f'<li><a href="{url}">{entry[0]}</a> {filesize(entry[1])}</li>')
    body.write(f'</ul>{postfix}')

    body.write(f'{prefix}<h1>tls connections</h1><ul>')
    for entry in sorted(tls_entries_by_count.items(), key=lambda i:i[1], reverse=True):
        url = kibana.url(f'tls.sni:{entry[0]}', start)
        body.write(f'<li><a href="{url}">{entry[0]}</a> {entry[1]}</li>')
    body.write(f'</ul>{postfix}')

    body.write(f'{prefix}<h1>tls bandwidth</h1><ul>')
    for entry in sorted(tls_entries_by_bandwidth.items(), key=lambda i:i[1], reverse=True):
        url = kibana.url(f'tls.sni:{entry[0]}', start)
        body.write(f'<li><a href="{url}">{entry[0]}</a> {filesize(entry[1])}</li>')
    body.write(f'</ul>{postfix}')

    body.write('</body></html>')

    gmail.send(None, 'frosty http-stats', body.getvalue(), html=True)
