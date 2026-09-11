#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from urllib.parse import urlparse, urlencode
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode
    from urllib2 import urlopen, Request, HTTPError

import time
import plugins
import re
import base64


class Plugin(plugins.BasePlugin):
    __name__ = 'httpd'

    def run(self, config):
        '''
        Apache/httpd status page metrics
        '''

        prev_cache = self.get_agent_cache() or {}
        next_cache = {'ts': time.time()}

        try:
            url = config.get('httpd', 'status_page_url')

            # Optional Basic Auth
            #Add to [httpd] in config file:
            #username = your_username   ; optional
            #password = your_password   ; optional

            username = config.get('httpd', 'username', fallback=None)
            password = config.get('httpd', 'password', fallback=None)

            request = Request(url)

            if username and password:
                credentials = f'{username}:{password}'
                encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
                request.add_header('Authorization', f'Basic {encoded_credentials}')

            data = urlopen(request).read().decode('utf-8')

        except Exception as e:
            return False

        exp = re.compile(r'^([A-Za-z ]+):\s+(.+)$')
        results = {}

        def parse_score_board(sb):
            return [
                ('IdleWorkers', sb.count('_')),
                ('ReadingWorkers', sb.count('R')),
                ('WritingWorkers', sb.count('W')),
                ('KeepaliveWorkers', sb.count('K')),
                ('DnsWorkers', sb.count('D')),
                ('ClosingWorkers', sb.count('C')),
                ('LoggingWorkers', sb.count('L')),
                ('FinishingWorkers', sb.count('G')),
                ('CleanupWorkers', sb.count('I')),
            ]

        for line in data.split('\n'):
            if line:
                m = exp.match(line)
                if m:
                    k, v = m.group(1), m.group(2)

                    # Skip non-metric fields
                    ignored_keys = {
                        'IdleWorkers', 'Server Built', 'CurrentTime', 'RestartTime',
                        'ServerUptime', 'CPULoad', 'CPUUser', 'CPUSystem',
                        'CPUChildrenUser', 'CPUChildrenSystem', 'ReqPerSec'
                    }
                    if k in ignored_keys:
                        continue

                    if k == 'Total Accesses':
                        results['requests_per_second'] = self.absolute_to_per_second(k, int(v), prev_cache)
                        next_cache['Total Accesses'] = int(v)

                    elif k == 'Scoreboard':
                        for sb_kv in parse_score_board(v):
                            results[sb_kv[0]] = sb_kv[1]
                    else:
                        results[k] = v

        self.set_agent_cache(next_cache)
        return results


if __name__ == '__main__':
    Plugin().execute()
    