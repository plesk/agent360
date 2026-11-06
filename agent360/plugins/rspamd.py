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
calculated over the interval since the previous call; on the first call (or
when no messages were scanned in the interval) they fall back to lifetime
ratios calculated from the counters.

rspamc must be able to reach the controller. By default it uses
localhost:11334, which Rspamd trusts without a password. For a password
protected controller, put the (read-only) controller password in
rspamc.conf, readable only by the user running the agent. Do not add
addresses to the controller's secure_ip just for this plugin, and do not
pass the password on the command line, it would be visible in the process
list. Only a local controller is supported: the controller speaks plain HTTP,
so the password would cross the network unencrypted for a remote one.

Configuration section example:
[rspamd]
enabled = yes
; optional, absolute path to rspamc, otherwise rspamc is searched only in
; the standard system directories (/usr/bin, /usr/local/bin, /bin, /usr/sbin,
; /usr/local/sbin, /sbin), never in PATH
; binary = /usr/bin/rspamc
; optional, local controller address passed to rspamc as -h, only
; localhost, 127.0.0.1 or [::1] with an optional port are accepted
; host = localhost:11334
; optional, seconds to wait for each rspamc call (default 10)
; timeout = 10

Notes:
- This plugin intentionally omits low-value/raw internals to keep payloads
  compact for monitoring.
"""

from __future__ import print_function, unicode_literals

import json
import os
import re
import subprocess
import threading
import time

import plugins


class Plugin(plugins.BasePlugin):
    __name__ = 'rspamd'

    _SYSTEM_DIRS = ('/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/usr/local/sbin', '/sbin')
    _LOCAL_HOST = re.compile(r'^(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?$')

    @staticmethod
    def _which(command):
        # PATH is deliberately not used: the agent usually runs as root and a
        # user-writable PATH entry would let someone run their own binary.
        for folder in Plugin._SYSTEM_DIRS:
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
                return configured, None
            return None, 'configured binary must be an absolute path to an executable'
        found = Plugin._which('rspamc')
        return found, (None if found else 'rspamc binary not found')

    @staticmethod
    def _get_option(config, option, default=None):
        try:
            value = config.get('rspamd', option)
        except Exception:
            return default
        return value if value else default

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

    def _run_json(self, cmd, timeout=10):
        # Output of rspamc is never returned to the caller, errors are generic
        # messages so that nothing from the controller leaves the server.
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        except Exception:
            return None, 'cannot execute rspamc'

        # Python 2 compatible timeout: kill the process from a timer thread.
        timed_out = []

        def kill():
            timed_out.append(True)
            try:
                proc.kill()
            except Exception:
                pass

        timer = threading.Timer(timeout, kill)
        timer.daemon = True
        timer.start()
        try:
            stdout_raw, _stderr_raw = proc.communicate()
        finally:
            timer.cancel()

        if timed_out:
            return None, 'rspamc timed out'
        if proc.returncode != 0:
            return None, 'rspamc failed (exit code %s)' % proc.returncode

        json_text = self._extract_json_text(self._to_text(stdout_raw).strip())
        if not json_text:
            return None, 'rspamc returned no JSON payload'

        try:
            payload = json.loads(self._sanitize_json_text(json_text))
        except Exception:
            return None, 'invalid JSON from rspamc'
        if not isinstance(payload, dict):
            return None, 'unexpected JSON from rspamc'
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

    @staticmethod
    def _interval_pct(rates, key, total_key, lifetime_pct):
        # Ratio over the interval since the previous call, lifetime ratio when
        # there is nothing to calculate it from.
        if rates[total_key] > 0:
            return round(min(rates[key] * 100.0 / rates[total_key], 100.0), 4)
        return lifetime_pct

    def run(self, config):
        binary, binary_error = self._find_binary(config)
        if not binary:
            return {'health': {'available': 0}, 'error': binary_error}

        base = [binary]
        host = self._get_option(config, 'host')
        if host:
            if not self._LOCAL_HOST.match(host):
                return {'health': {'available': 0}, 'error': 'host must be a local controller address'}
            base += ['-h', host]
        timeout = self._as_float(self._get_option(config, 'timeout'), 10.0)
        if timeout <= 0:
            timeout = 10.0

        stat, stat_error = self._run_json(base + ['stat', '-j'], timeout)
        uptime, uptime_error = self._run_json(base + ['uptime', '-j'], timeout)

        if not stat and not uptime:
            return {
                'health': {'available': 0},
                'error': stat_error or uptime_error or 'rspamc unavailable',
            }

        actions = (stat or {}).get('actions', {})
        if not isinstance(actions, dict):
            actions = {}

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

        scan_times = (stat or {}).get('scan_times')
        if not isinstance(scan_times, list):
            scan_times = []
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
                'spam_ratio_pct': self._interval_pct(
                    rates, 'spam_count', 'scanned', self._pct(spam_count, scanned)),
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
                'reject_ratio_pct': self._interval_pct(
                    rates, 'reject_count', 'scanned', self._pct(reject_count, scanned)),
                'greylist_ratio_pct': self._interval_pct(
                    rates, 'greylist_count', 'scanned', self._pct(greylist_count, scanned)),
                'reject_count_per_second': rates['reject_count'],
                'soft_reject_count_per_second': rates['soft_reject_count'],
                'greylist_count_per_second': rates['greylist_count'],
                'add_header_count_per_second': rates['add_header_count'],
                'rewrite_subject_count_per_second': rates['rewrite_subject_count'],
                'no_action_count_per_second': rates['no_action_count'],
            },
            'performance': {
                'scan_time_avg_sec': self._avg(scan_times),
                'scan_time_last_sec': scan_time_last,
            },
        }

        return result


if __name__ == '__main__':
    Plugin().execute()
