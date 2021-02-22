import requests

import datetime
import logging
from typing import Dict, Iterator, List, Union


def search(
    query: Dict[str, Union[Dict, List, int]],
    start: datetime.datetime,
      end: datetime.datetime = datetime.datetime.now()
) -> Iterator[Dict[str, Union[Dict, List, int, str]]]:

    # Ref: https://www.elastic.co/guide/en/elasticsearch/reference/current/paginate-search-results.html#search-after
    #      https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html

    dates = [(start + datetime.timedelta(days=i)).date() for i in range((end-start).days + 2)]
    indices = [d.strftime('suricata-%Y%m%d') for d in dates]

    present = []
    for index in indices:
        resp = requests.get(f'http://127.0.0.1:9200/_cat/indices/{index}?format=json', timeout=100)
        if resp.status_code == 200:
            present += [index]

    if len(present) < len(indices):
        logging.warning('%d indices not present', len(indices) - len(present))
    indices = present

    url = f'http://127.0.0.1:9200/{",".join(indices)}/_search'

    count = 0
    while True:
        resp = requests.post(url, json=query, timeout=100)
        resp.raise_for_status()

        hits = resp.json()['hits']['hits']
        if len(hits) == 0:
            break

        for hit in hits:
            yield hit
            count += 1

        lastsort = hits[-1]['sort']
        query['search_after'] = lastsort

    logging.info('%d records found', count)


_flow_indices_cache = {}

def flow(
      flowid: int,
       start: datetime.datetime,
         end: datetime.datetime = datetime.datetime.now(),
    timezone: str = '-05:00'
) -> Union[Dict[str, Union[Dict, List, int, str]], None]:

    dates = [(start + datetime.timedelta(days=i)).date() for i in range((end-start).days + 2)]
    indices = [d.strftime('suricata-%Y%m%d') for d in dates]

    global _flow_indices_cache
    key = ','.join(indices)
    if key in _flow_indices_cache:
        indices = _flow_indices_cache[key]
    else:
        present = []
        for index in indices:
            resp = requests.get(f'http://127.0.0.1:9200/_cat/indices/{index}?format=json', timeout=100)
            if resp.status_code == 200:
                present += [index]

        if len(present) < len(indices):
            logging.warning('%d indices not present', len(indices) - len(present))
        _flow_indices_cache[key] = indices = present

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'match': {
                            'event_type': 'flow'
                        }
                    },
                    {
                        'match': {
                            'flow_id': flowid
                        }
                    },
                    {
                        'range': {
                            'timestamp': {
                                'gte': start.isoformat(),
                                'lte': 'now',
                                'time_zone': timezone
                            }
                        }
                    }
                ]
            }
        }
    }

    url = f'http://127.0.0.1:9200/{",".join(indices)}/_search'

    resp = requests.post(url, json=query, timeout=100)
    resp.raise_for_status()

    hits = resp.json()['hits']['hits']
    assert len(hits) in [0, 1]
    return None if len(hits) == 0 else hits[0]

