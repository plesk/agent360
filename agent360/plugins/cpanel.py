#!/usr/bin/env python
# -*- coding: utf-8 -*-
import plugins
import subprocess
import json
import re

class Plugin(plugins.BasePlugin):
    __name__ = 'cpanel'

    UNITS = {"B": 1, "K": 2 ** 10, "M": 2 ** 20, "G": 2 ** 30, "T": 2 ** 40}
    SIZE_RE = re.compile(r'^\s*(\d+(?:\.\d+)?)\s*([BKMGT]?)B?\s*$', re.IGNORECASE)

    def to_bytes(self, size):
        '''
        Convert a size string reported by cPanel ("12M", "1.5G", "512B", "0",
        "10 MB") to bytes. Returns None when cPanel reports no size, for
        example "none" when disk quotas are not enabled or "unlimited".
        '''
        match = self.SIZE_RE.match(str(size))
        if not match:
            return None
        number, unit = match.groups()
        return int(float(number) * self.UNITS[unit.upper() or "B"])

    def run(self, config):
        '''
        Plugin to collect cpanel user accounts
        To enable add to /etc/agent360-custom.ini:
        [cpanel]
        enabled = yes
        '''

        data = subprocess.check_output(['whmapi1', '--output=jsonpretty',  'listaccts'])

        results = {}
        accounts = json.loads(data)
        for account in accounts['data']['acct']:
            results[account['user']] = {
                'inodesused': account['inodesused'],
                'is_locked': account['is_locked'],
                'has_backup': account['has_backup'],
                'outgoing_mail_hold': account['outgoing_mail_hold'],
                'outgoing_mail_suspended': account['outgoing_mail_suspended'],
                'suspended': account['suspended'],
            }
            # Without disk quotas cPanel reports "none": omit the metric then,
            # instead of failing the whole plugin or reporting a false 0.
            diskused = self.to_bytes(account['diskused'])
            if diskused is not None:
                results[account['user']]['diskused_bytes'] = diskused
        return results


if __name__ == '__main__':
    Plugin().execute()
