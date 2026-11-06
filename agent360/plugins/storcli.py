#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
import re
import subprocess
import plugins


class Plugin(plugins.BasePlugin):
    __name__ = 'storcli'

    CANDIDATES = ['storcli64', 'storcli', '/opt/MegaRAID/storcli/storcli64', '/usr/sbin/storcli64']

    def run(self, config):
        '''
        Monitor LSI/Broadcom MegaRAID controllers, virtual drives and physical
        drives using StorCLI (successor of the EOL MegaCLI utility):
        https://docs.broadcom.com/docs/storcli

        Requires sudo access to storcli (whereis storcli64) add to /etc/sudoers:
        agent360 ALL=(ALL) NOPASSWD: /REPLACE/PATH/TO/storcli64

        To enable add to /etc/agent360.ini:
        [storcli]
        enabled = yes
        ; optional, defaults to storcli64 found in PATH or /opt/MegaRAID/storcli
        ; binary = /opt/MegaRAID/storcli/storcli64
        '''
        binary = self.find_binary(config)
        if binary is None:
            return "Could not find storcli binary"

        results = {}

        controllers = self.storcli(binary, '/call show all')
        if controllers is None:
            return "Could not load storcli controller data"
        for ctrl in controllers:
            self.parse_controller(ctrl, results)

        # Virtual and physical drive queries fail on controllers without
        # any configured volumes, that is not an error.
        for ctrl in self.storcli(binary, '/call/vall show all') or []:
            self.parse_virtual_drives(ctrl, results)
        for ctrl in self.storcli(binary, '/call/eall/sall show all') or []:
            self.parse_physical_drives(ctrl, results)

        return results

    def find_binary(self, config):
        candidates = list(self.CANDIDATES)
        try:
            configured = config.get('storcli', 'binary')
            if configured:
                candidates.insert(0, configured)
        except Exception:
            pass
        for candidate in candidates:
            try:
                p = subprocess.Popen([candidate, '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p.communicate()
                return candidate
            except Exception:
                continue
        return None

    def storcli(self, binary, args):
        '''
        Run storcli and return the list of controller responses or None.
        '''
        cmd = [binary] + args.split() + ['J']
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            cmd = ['sudo', '-n'] + cmd
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out = p.communicate()[0].decode('utf-8', 'replace')
            data = json.loads(out)
            return data['Controllers']
        except Exception:
            return None

    @staticmethod
    def controller_id(ctrl):
        return int(ctrl.get('Command Status', {}).get('Controller', 0))

    @staticmethod
    def to_int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            m = re.match(r'\s*(-?\d+)', str(value))
            return int(m.group(1)) if m else default

    def parse_controller(self, ctrl, results):
        cid = self.controller_id(ctrl)
        data = ctrl.get('Response Data', {})
        status = data.get('Status', {})
        hw = data.get('HW Cfg', {})
        basics = data.get('Basics', {})

        info = {
            'model': basics.get('Model', ''),
            'status': status.get('Controller Status', ''),
            'optimal': 1 if status.get('Controller Status') == 'Optimal' else 0,
            'memory_correctable_errors': self.to_int(status.get('Memory Correctable Errors')),
            'memory_uncorrectable_errors': self.to_int(status.get('Memory Uncorrectable Errors')),
            'bbu_status': status.get('BBU Status', ''),
            'virtual_drives': self.to_int(data.get('Virtual Drives')),
            'physical_drives': self.to_int(data.get('Physical Drives')),
        }
        temp = hw.get('ROC temperature(Degree Celsius)')
        if temp is not None:
            info['roc_temperature'] = self.to_int(temp)
        results['controller_{}'.format(cid)] = info

    def parse_virtual_drives(self, ctrl, results):
        cid = self.controller_id(ctrl)
        data = ctrl.get('Response Data', {})
        for key, rows in data.items():
            m = re.match(r'^/c(\d+)/v(\d+)$', key)
            if not m or not rows:
                continue
            vid = int(m.group(2))
            row = rows[0]
            props = data.get('VD{} Properties'.format(vid), {})
            state = row.get('State', '')
            results['vd_{}_{}'.format(cid, vid)] = {
                'name': row.get('Name', props.get('Name', '')) or '',
                'raid_level': row.get('TYPE', ''),
                'size': row.get('Size', ''),
                'state': state,
                'optimal': 1 if state == 'Optl' else 0,
                'access': row.get('Access', ''),
                'consistent': 1 if row.get('Consist') == 'Yes' else 0,
                'stripe_size': props.get('Strip Size', ''),
                'number_of_drives': self.to_int(props.get('Number of Drives Per Span', props.get('Number of Drives'))),
                'span_depth': self.to_int(props.get('Span Depth')),
                'default_cache_policy': props.get('Default Cache Policy', ''),
                'current_cache_policy': props.get('Current Cache Policy', ''),
                'disk_cache_policy': props.get('Disk Cache Policy', ''),
                'encryption': props.get('Encryption', ''),
            }

    def parse_physical_drives(self, ctrl, results):
        cid = self.controller_id(ctrl)
        data = ctrl.get('Response Data', {})
        for key, rows in data.items():
            m = re.match(r'^Drive /c(\d+)/e(\d+)/s(\d+)$', key)
            if not m or not rows:
                continue
            eid, slot = m.group(2), m.group(3)
            row = rows[0]
            prefix = 'Drive /c{}/e{}/s{}'.format(cid, eid, slot)
            detail = data.get(prefix + ' - Detailed Information', {})
            counters = detail.get(prefix + ' State', {})
            attrs = detail.get(prefix + ' Device attributes', {})
            state = row.get('State', '')
            drive = {
                'state': state,
                # Onln = member of a drive group, UGood = unconfigured good,
                # GHS/DHS = hot spare
                'healthy': 1 if state in ('Onln', 'UGood', 'GHS', 'DHS', 'JBOD') else 0,
                'media': row.get('Med', ''),
                'interface': row.get('Intf', ''),
                'size': row.get('Size', ''),
                'model': (row.get('Model', '') or '').strip(),
                'media_error_count': self.to_int(counters.get('Media Error Count')),
                'other_error_count': self.to_int(counters.get('Other Error Count')),
                'predictive_failure_count': self.to_int(counters.get('Predictive Failure Count')),
                'smart_alert': 1 if counters.get('S.M.A.R.T alert flagged by drive') == 'Yes' else 0,
            }
            if attrs.get('Drive Temperature') is not None:
                drive['temperature'] = self.to_int(attrs.get('Drive Temperature'))
            results['pd_{}_{}_{}'.format(cid, eid, slot)] = drive


if __name__ == '__main__':
    Plugin().execute()
