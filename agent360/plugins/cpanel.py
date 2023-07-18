#!/usr/bin/env python
# -*- coding: utf-8 -*-
import plugins
import subprocess
import json
import re

class Plugin(plugins.BasePlugin):
    __name__ = 'cpanel'

    def to_bytes(self, size):
        size = size.upper()
        units = {"B": 1, "K": 2 ** 10, "M": 2 ** 20, "G": 2 ** 30, "T": 2 ** 40}

        if not re.match(r' ', size):
            size = re.sub(r'([KMGT])', r' \1', size)
        number, unit = [string.strip() for string in size.split()]
        return int(float(number) * units[unit])

    def run(self, config):
        '''
        Plugin to collect cpanel user accounts
        To enable add to /etc/agent360.ini:
        [cpanel]
        enabled = yes
        '''

        data = subprocess.check_output(['whmapi1', '--output=jsonpretty',  'listaccts'])

        results = {}
        accounts = json.loads(data)
        for account in accounts['data']['acct']:
            results[account['user']] = {
                'diskused_bytes': self.to_bytes(account['diskused']),
                'inodesused': account['inodesused'],
                'is_locked': account['is_locked'],
                'has_backup': account['has_backup'],
                'outgoing_mail_hold': account['outgoing_mail_hold'],
                'outgoing_mail_suspended': account['outgoing_mail_suspended'],
                'suspended': account['suspended'],
            }
        return results


if __name__ == '__main__':
    Plugin().execute()
