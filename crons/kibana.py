import requests

import datetime


_index_pattern_guid_cache = None

def url(
    query: str,
    start: datetime.datetime,
      end: datetime.datetime = datetime.datetime.now()
) -> str:

    global _index_pattern_guid_cache
    if _index_pattern_guid_cache is None:
        resp = requests.get('http://127.0.0.1:5601/api/saved_objects/_find',
                             params = {'type':'index-pattern', 'search':'suricata-*'},
                            timeout = 100)
        resp.raise_for_status()
        for pattern in resp.json()['saved_objects']:
            guid = pattern.get('id')
            if guid is None:
                continue
            if pattern.get('attributes', {}).get('title') == 'suricata-*':
                _index_pattern_guid_cache = guid
                break

        assert _index_pattern_guid_cache is not None

    url = 'http://127.0.0.1:5601/app/discover#/?' + \
          '_g=(filters:!(),refreshInterval:(pause:!t,value:0),' + \
          f"time:(from:'{start}',to:'{end}'))&" + \
          '_a=(columns:!(event_type,src_ip,src_port,dest_ip,dest_port,proto,app_proto),' + \
          f"filters:!(),index:'{_index_pattern_guid_cache}',interval:auto,sort:!()," + \
          f"query:(language:kuery,query:'{query}'))"

    return url
