#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""agent360 Rspamd monitor plugin.

Returned metrics are grouped in nested dicts:
- meta: version
- health: available, auth_ok, read_only, uptime_seconds, stat_ok, uptime_ok
- messages: scanned, learned, spam_count, ham_count, spam_ratio_pct
  (+ <name>_per_second for the counters)
- actions: reject_count, soft_reject_count, greylist_count,
  add_header_count, rewrite_subject_count, no_action_count,
  reject_ratio_pct, greylist_ratio_pct (+ <name>_per_second for the counters)
- performance: scan_time_avg_sec, scan_time_last_sec

Counters are values since the start of Rspamd, *_per_second values are
calculated from them using cached values from the previous call. Ratios are
calculated from the counters, so they are lifetime ratios.

The controller must be reachable by rspamc without a password (default
localhost:11334 with the agent's address in secure_ip) or rspamc must be
configured in rspamc.conf.

Configuration section example:
[rspamd]
enabled = yes
; optional, absolute path to rspamc, defaults to rspamc found in PATH
; binary = /usr/bin/rspamc

Notes:
- This plugin intentionally omits low-value/raw internals to keep payloads
  compact for monitoring.
"""

from __future__ import print_function, unicode_literals

import json
import os
import re
import subprocess
import time

import plugins


class Plugin(plugins.BasePlugin):
    __name__ = 'rspamd'

    @staticmethod
    def _which(command):
        # Compatible replacement for shutil.which for older Python versions.
        # Only absolute PATH entries are considered.
        for folder in os.environ.get('PATH', '').split(os.pathsep):
            if not folder or not os.path.isabs(folder):
                continue
            candidate = os.path.join(folder, command)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    @staticmethod
    def _find_binary(config):
        try:
            configured = config.get('rspamd', 'binary')
        except Exception:
            configured = None
        if configured:
            if os.path.isabs(configured) and os.access(configured, os.X_OK):
                return configured
            return None
        return Plugin._which('rspamc')

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
        # Quoted strings are matched first and kept untouched.
        def replace(match):
            return match.group(0) if match.group(1) is None else 'null'

        return re.sub(
            r'"(?:[^"\\]|\\.)*"|(?<![A-Za-z0-9_])(nan|inf|-inf)(?![A-Za-z0-9_])',
            replace, text, flags=re.IGNORECASE)

    def _run_json(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout_raw, stderr_raw = proc.communicate()
        stdout = self._to_text(stdout_raw).strip()
        stderr = self._to_text(stderr_raw).strip()

        if proc.returncode != 0:
            return None, 'command failed (%s): %s' % (proc.returncode, (stderr or stdout)[:200])

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

    def _rates(self, counters):
        # Counters are values since the start of Rspamd, per second values are
        # calculated from the values cached on the previous call.
        now = time.time()
        prev_cache = self.get_agent_cache()
        next_cache = {'ts': now}
        rates = {}
        for key, value in counters.items():
            next_cache[key] = value
            try:
                elapsed = now - prev_cache['ts']
                if elapsed <= 0:
                    raise ValueError
                if value >= prev_cache[key]:
                    rates[key] = (value - prev_cache[key]) / elapsed
                else:  # Rspamd was restarted after previous caching
                    rates[key] = value / elapsed
            except (KeyError, ValueError):  # No cache yet, can't calculate
                rates[key] = 0.0
        self.set_agent_cache(next_cache)
        return rates

    def run(self, config):
        binary = self._find_binary(config)
        if not binary:
            return {
                'available': 0,
                'error': 'rspamc binary not found',
            }

        stat, stat_error = self._run_json([binary, 'stat', '-j'])
        uptime, uptime_error = self._run_json([binary, 'uptime', '-j'])

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

        rates = self._rates({
            'scanned': scanned,
            'learned': learned,
            'spam_count': spam_count,
            'ham_count': ham_count,
            'reject_count': reject_count,
            'soft_reject_count': soft_reject_count,
            'greylist_count': greylist_count,
            'add_header_count': add_header_count,
            'rewrite_subject_count': rewrite_subject_count,
            'no_action_count': no_action_count,
        })

        scan_times = (stat or {}).get('scan_times') or []
        if scan_times:
            scan_time_last = self._as_float(scan_times[-1])
        else:
            scan_time_last = self._as_float((stat or {}).get('scan_time', (uptime or {}).get('scan_time', 0.0)))

        # A successful stat call means the controller accepted the request.
        auth = (uptime or {}).get('auth', (stat or {}).get('auth'))
        auth_ok = (auth == 'ok') if auth is not None else not stat_error

        result = {
            'meta': {
                'version': (stat or {}).get('version', (uptime or {}).get('version', 'unknown')),
            },
            'health': {
                'available': 1,
                'auth_ok': 1 if auth_ok else 0,
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
                'scanned_per_second': rates['scanned'],
                'learned_per_second': rates['learned'],
                'spam_count_per_second': rates['spam_count'],
                'ham_count_per_second': rates['ham_count'],
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
                'reject_count_per_second': rates['reject_count'],
                'soft_reject_count_per_second': rates['soft_reject_count'],
                'greylist_count_per_second': rates['greylist_count'],
                'add_header_count_per_second': rates['add_header_count'],
                'rewrite_subject_count_per_second': rates['rewrite_subject_count'],
                'no_action_count_per_second': rates['no_action_count'],
            },
            'performance': {
                'scan_time_avg_sec': self._avg((stat or {}).get('scan_times', [])),
                'scan_time_last_sec': scan_time_last,
            },
        }

        return result


if __name__ == '__main__':
    Plugin().execute()
