#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""agent360 Rspamd monitor plugin.

Returned metric groups:
- Health: available, auth_ok, read_only, version, uptime_seconds
- Volume: scanned, learned
- Mail classification: spam_count, ham_count
- Actions: reject_count, soft_reject_count, greylist_count,
  add_header_count, rewrite_subject_count, no_action_count
- Ratios: spam_ratio_pct, reject_ratio_pct, greylist_ratio_pct
- Performance: scan_time_avg_sec, scan_time_last_sec

Configuration section example:
[rspamd]
enabled = yes

Notes:
- This plugin intentionally omits low-value/raw internals to keep payloads
  compact for monitoring.
"""

from __future__ import print_function, unicode_literals

import json
import os
import re
import subprocess

import plugins


class Plugin(plugins.BasePlugin):
    __name__ = 'rspamd'

    @staticmethod
    def _which(command):
        # Compatible replacement for shutil.which for older Python versions.
        path = os.environ.get('PATH', '')
        if not path:
            return None

        is_windows = os.name == 'nt'
        exts = ['']
        if is_windows:
            pathext = os.environ.get('PATHEXT', '.EXE;.BAT;.CMD;.COM')
            exts = [ext.lower() for ext in pathext.split(os.pathsep) if ext]

        for folder in path.split(os.pathsep):
            folder = folder.strip('"')
            if not folder:
                continue

            candidate = os.path.join(folder, command)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

            if is_windows and not os.path.splitext(command)[1]:
                for ext in exts:
                    candidate_ext = candidate + ext
                    if os.path.isfile(candidate_ext) and os.access(candidate_ext, os.X_OK):
                        return candidate_ext
        return None

    def _command(self, subcommand):
        rspamc_path = self._which('rspamc')
        if not rspamc_path:
            return None

        cmd = [rspamc_path]
        cmd.extend([subcommand, '-j'])
        return cmd

    @staticmethod
    def _to_text(raw_value):
        if isinstance(raw_value, bytes):
            try:
                return raw_value.decode('utf-8')
            except Exception:
                return raw_value.decode('utf-8', 'replace')
        return raw_value or ''

    @staticmethod
    def _extract_json_text(text):
        if not text:
            return None

        start = text.find('{')
        end = text.rfind('}')
        if start == -1 or end == -1 or end < start:
            return None

        return text[start:end + 1]

    @staticmethod
    def _sanitize_json_text(text):
        if not text:
            return text

        # rspamc may emit non-JSON float tokens such as lowercase nan/inf.
        return re.sub(r'(?<![A-Za-z0-9_"])(nan|inf|-inf)(?![A-Za-z0-9_"])', 'null', text, flags=re.IGNORECASE)

    def _run_json(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout_raw, stderr_raw = proc.communicate()
        stdout = self._to_text(stdout_raw).strip()
        stderr = self._to_text(stderr_raw).strip()

        if proc.returncode != 0:
            return None, 'command failed (%s): %s' % (proc.returncode, stderr or stdout)

        json_text = self._extract_json_text(stdout)
        if not json_text:
            return None, 'rspamc returned no JSON payload'

        json_text = self._sanitize_json_text(json_text)

        try:
            payload = json.loads(json_text)
        except Exception:
            return None, 'invalid JSON from rspamc: %s' % stdout[:200]
        return payload, None

    @staticmethod
    def _as_int(value, default=0):
        try:
            return int(value)
        except Exception:
            return default

    @staticmethod
    def _as_float(value, default=0.0):
        try:
            return float(value)
        except Exception:
            return default

    @staticmethod
    def _pct(part, total):
        if total <= 0:
            return 0.0
        return round((float(part) * 100.0) / float(total), 4)

    @staticmethod
    def _avg(values):
        if not values:
            return 0.0
        numeric = []
        for value in values:
            try:
                numeric.append(float(value))
            except Exception:
                continue
        if not numeric:
            return 0.0
        return round(sum(numeric) / float(len(numeric)), 6)

    def run(self, config):
        stat_cmd = self._command('stat')
        uptime_cmd = self._command('uptime')

        if not stat_cmd or not uptime_cmd:
            return {
                'available': 0,
                'error': 'rspamc binary not found in PATH',
            }

        stat, stat_error = self._run_json(stat_cmd)
        uptime, uptime_error = self._run_json(uptime_cmd)

        if not stat and not uptime:
            return {
                'available': 0,
                'error': stat_error or uptime_error or 'rspamc unavailable',
            }

        actions = (stat or {}).get('actions', {})

        scanned = self._as_int((stat or {}).get('scanned', (uptime or {}).get('scanned', 0)))
        learned = self._as_int((stat or {}).get('learned', (uptime or {}).get('learned', 0)))
        spam_count = self._as_int((stat or {}).get('spam_count', 0))
        ham_count = self._as_int((stat or {}).get('ham_count', 0))
        reject_count = self._as_int(actions.get('reject', (uptime or {}).get('reject', 0)))
        soft_reject_count = self._as_int(actions.get('soft reject', (uptime or {}).get('soft_reject', 0)))
        greylist_count = self._as_int(actions.get('greylist', (uptime or {}).get('greylist', 0)))
        add_header_count = self._as_int(actions.get('add header', (uptime or {}).get('probable', 0)))
        rewrite_subject_count = self._as_int(actions.get('rewrite subject', 0))
        no_action_count = self._as_int(actions.get('no action', (uptime or {}).get('clean', 0)))

        result = {
            'meta': {
                'version': (stat or {}).get('version', (uptime or {}).get('version', 'unknown')),
            },
            'health': {
                'available': 1,
                'auth_ok': 1 if (uptime or {}).get('auth') == 'ok' else 0,
                'read_only': 1 if bool((stat or {}).get('read_only', (uptime or {}).get('read_only', False))) else 0,
                'uptime_seconds': self._as_int((stat or {}).get('uptime', (uptime or {}).get('uptime', 0))),
                'stat_ok': 0 if stat_error else 1,
                'uptime_ok': 0 if uptime_error else 1,
            },
            'messages': {
                'scanned': scanned,
                'learned': learned,
                'spam_count': spam_count,
                'ham_count': ham_count,
                'spam_ratio_pct': self._pct(spam_count, scanned),
            },
            'actions': {
                'reject_count': reject_count,
                'soft_reject_count': soft_reject_count,
                'greylist_count': greylist_count,
                'add_header_count': add_header_count,
                'rewrite_subject_count': rewrite_subject_count,
                'no_action_count': no_action_count,
                'reject_ratio_pct': self._pct(reject_count, scanned),
                'greylist_ratio_pct': self._pct(greylist_count, scanned),
            },
            'performance': {
                'scan_time_avg_sec': self._avg((stat or {}).get('scan_times', [])),
                'scan_time_last_sec': self._as_float((stat or {}).get('scan_time', (uptime or {}).get('scan_time', 0.0)), 0.0),
            },
        }

        return result


if __name__ == '__main__':
    Plugin().execute()
