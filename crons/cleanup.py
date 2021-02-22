#!/usr/bin/env python3

import requests

import datetime


if __name__ == '__main__':
    resp = requests.get('http://127.0.0.1:9200/_cat/indices/suricata-*?format=json', timeout=100)
    resp.raise_for_status()
    indices = [index['index'] for index in resp.json()]

    date = int((datetime.date.today() - datetime.timedelta(days=90)).strftime('%Y%m%d'))
    indices_delete = [index for index in indices if int(index.split('-', maxsplit=1)[1]) < date]

    for index in indices_delete:
        resp = requests.delete(f'http://127.0.0.1:9200/{index}')
        resp.raise_for_status()
