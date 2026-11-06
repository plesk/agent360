#!/usr/bin/env python
# -*- coding: utf-8 -*-
#from past.builtins import basestring    # pip install future
try:
    from urllib.parse import urlparse, urlencode
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode
    from urllib2 import urlopen, Request, HTTPError
import sys
import time
import plugins
import json


class Plugin(plugins.BasePlugin):
    __name__ = 'phpfpm'

    def run(self, config):
        '''
        php-fpm status page metrics
        '''
        def ascii_encode_dict(data):
            ascii_encode = lambda x: x.encode('ascii') if isinstance(x, unicode) else x
            return dict(map(ascii_encode, pair) for pair in data.items())

        results = dict()
        my_pools = config.get(__name__, 'status_page_url').split(',')
        prev_cache = self.get_agent_cache()  # Get absolute values from previous check
        next_cache = prev_cache.copy()
        all_pools_up = True
        for pool in my_pools:
            try:
                request = Request(pool)
                raw_response = urlopen(request)
                data = raw_response.read().decode('utf-8')
#                pprint.pprint(data)
                if sys.version_info >= (3,):
                    j = json.loads(data)
                else:
                    j = json.loads(data, object_hook=ascii_encode_dict)
                pool_results = {}
                for k, v in j.items():
                    pool_results[k.replace(" ", "_")] = v
                accepted_conn = int(pool_results['accepted_conn'])
                sample_time = time.time()

                # Publish only validated samples; failed pools keep their cache.
                results[j['pool']] = pool_results
                next_cache['%s_ts' % j['pool']] = sample_time
                next_cache['%s_accepted_conn' % j['pool']] = accepted_conn
            except Exception:
                all_pools_up = False
                continue

            try:
                if next_cache['%s_accepted_conn' % j['pool']] >= prev_cache['%s_accepted_conn' % j['pool']]:
                    results[j['pool']]['accepted_conn_per_second'] = \
                        (next_cache['%s_accepted_conn' % j['pool']] - prev_cache['%s_accepted_conn' % j['pool']]) / \
                        (next_cache['%s_ts' % j['pool']] - prev_cache['%s_ts' % j['pool']])
                else:  # Was restarted after previous caching
                    results[j['pool']]['accepted_conn_per_second'] = \
                        next_cache['%s_accepted_conn' % j['pool']] / \
                        (next_cache['%s_ts' % j['pool']] - prev_cache['%s_ts' % j['pool']])
            except KeyError:  # No cache yet, can't calculate
                results[j['pool']]['accepted_conn_per_second'] = 0.0

        # Cache absolute values for next check calculations
        self.set_agent_cache(next_cache)

        results['up'] = 1 if all_pools_up else 0
        return results


if __name__ == '__main__':
    Plugin().execute()
