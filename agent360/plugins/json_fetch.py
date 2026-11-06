#!/usr/bin/env python
"""Plugin that fetches JSON payloads from one or more configured endpoints.

Example configuration:

[json_fetch]
enabled = yes
url_weather = https://api.example.com/weather/today
method_weather = GET
headers_weather = {"Accept":"application/json"}
timeout_weather = 8
url_fridge = https://api.example.com/fridge
method_fridge = GET
headers_fridge = {"Accept":"application/json"}
timeout_fridge = 5

Only GET requests over http/https are supported. Redirects are followed only
within the same host (and never from https to http), so credentials and custom
headers are not forwarded elsewhere. Credentials in the config are sent with
every request; use https:// URLs when auth_<name> or username_/password_<name>
is set.
"""

from __future__ import print_function, unicode_literals

import base64
import json
import logging
import math
import re

try:
    from urllib.request import Request, HTTPRedirectHandler, build_opener
    from urllib.error import HTTPError, URLError
except Exception:
    from urllib2 import Request, HTTPRedirectHandler, build_opener, HTTPError, URLError

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

import plugins


DEFAULT_TIMEOUT = 10
MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MiB
MAX_METRICS_PER_ENDPOINT = 200
DISABLED_VALUES = ('no', 'false', '0', 'off')
REQUEST_HEADERS = {
    'Accept': 'application/json',
    'User-Agent': 'agent360-json-fetch/2026.07',
}


def _reject_constant(name):
    # json.loads() accepts NaN/Infinity by default; they are not valid JSON
    # when the agent serializes its report.
    raise ValueError('invalid constant %s' % name)


class _SameHostRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only within the same host, never downgrading https.

    urllib forwards all request headers (including Authorization and custom
    API-key headers) to the redirect target, so cross-host redirects would
    leak credentials.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urlparse(req.get_full_url())
        new = urlparse(newurl)
        if new.scheme not in ('http', 'https') or                 (old.scheme == 'https' and new.scheme != 'https') or                 (old.hostname or '').lower() != (new.hostname or '').lower():
            return None
        return HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


class Plugin(plugins.BasePlugin):
    __name__ = 'json_fetch'

    def _parse_headers(self, raw_value):
        if not raw_value:
            return {}
        if isinstance(raw_value, dict):
            return raw_value

        text = raw_value.strip()
        if not text:
            return {}

        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            return parsed

        header_map = {}
        for fragment in text.split(';'):
            item = fragment.strip()
            if not item or ':' not in item:
                continue
            key, value = item.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key:
                header_map[key] = value
        return header_map

    def _safe_timeout(self, raw_value):
        try:
            timeout = float(raw_value)
        except Exception:
            return DEFAULT_TIMEOUT
        if timeout <= 0:
            return DEFAULT_TIMEOUT
        return timeout

    def _is_enabled(self, config, section, endpoint_name):
        option_name = 'enabled_' + endpoint_name
        if not config.has_option(section, option_name):
            return True
        value = config.get(section, option_name)
        return value.strip().lower() not in DISABLED_VALUES

    def _discover_endpoints(self, config):
        section = self.__name__
        if not config.has_section(section):
            return []

        endpoints = []
        for option_name in config.options(section):
            if not option_name.startswith('url_'):
                continue

            endpoint_name = option_name[len('url_'):].strip()
            if not endpoint_name or not self._is_enabled(config, section, endpoint_name):
                continue

            url = config.get(section, option_name)
            if urlparse(url).scheme not in ('http', 'https'):
                logging.warning('json_fetch: endpoint %s: unsupported URL scheme (only http/https allowed)',
                                endpoint_name)
                continue

            method = 'GET'
            method_key = 'method_' + endpoint_name
            if config.has_option(section, method_key):
                method = config.get(section, method_key).strip().upper() or 'GET'
            if method != 'GET':
                logging.warning('json_fetch: endpoint %s: unsupported method %s (only GET is allowed)',
                                endpoint_name, method)
                continue

            endpoint = {
                'name': endpoint_name,
                'url': url,
                'headers': {},
                'timeout': DEFAULT_TIMEOUT,
                'auth': None,
            }

            headers_key = 'headers_' + endpoint_name
            timeout_key = 'timeout_' + endpoint_name
            auth_key = 'auth_' + endpoint_name
            username_key = 'username_' + endpoint_name
            password_key = 'password_' + endpoint_name

            if config.has_option(section, headers_key):
                endpoint['headers'] = self._parse_headers(config.get(section, headers_key))
            if config.has_option(section, timeout_key):
                endpoint['timeout'] = self._safe_timeout(config.get(section, timeout_key))
            if config.has_option(section, auth_key):
                endpoint['auth'] = config.get(section, auth_key)
            elif config.has_option(section, username_key) or config.has_option(section, password_key):
                username = config.get(section, username_key) if config.has_option(section, username_key) else ''
                password = config.get(section, password_key) if config.has_option(section, password_key) else ''
                endpoint['auth'] = '%s:%s' % (username, password)

            if endpoint['auth'] and urlparse(url).scheme != 'https':
                logging.warning('json_fetch: endpoint %s: credentials are sent over unencrypted http',
                                endpoint_name)

            endpoints.append(endpoint)

        return endpoints

    def _encode_basic_auth(self, raw_auth):
        if isinstance(raw_auth, (list, tuple)):
            username = raw_auth[0] if len(raw_auth) > 0 else ''
            password = raw_auth[1] if len(raw_auth) > 1 else ''
        elif ':' in raw_auth:
            username, password = raw_auth.split(':', 1)
        else:
            username, password = raw_auth, ''

        credentials = '%s:%s' % (username, password)
        try:
            encoded = base64.b64encode(credentials.encode('utf-8'))
            return encoded.decode('ascii')
        except Exception:
            return base64.b64encode(credentials)

    def _build_request(self, endpoint):
        request = Request(endpoint['url'])
        merged_headers = dict(REQUEST_HEADERS)
        merged_headers.update(endpoint.get('headers') or {})
        for key, value in merged_headers.items():
            request.add_header(key, value)

        auth = endpoint.get('auth')
        if auth:
            request.add_header('Authorization', 'Basic %s' % self._encode_basic_auth(auth))
        return request

    def _decode_payload(self, raw_value):
        if isinstance(raw_value, bytes):
            try:
                return raw_value.decode('utf-8')
            except Exception:
                return raw_value.decode('utf-8', 'replace')
        return raw_value

    def _fetch_json(self, endpoint):
        try:
            opener = build_opener(_SameHostRedirectHandler)
            response = opener.open(self._build_request(endpoint), timeout=endpoint['timeout'])
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                logging.warning('json_fetch: endpoint %s: response larger than %d bytes',
                                endpoint['name'], MAX_RESPONSE_BYTES)
                return None
            payload = self._decode_payload(raw)
            return json.loads(payload, parse_constant=_reject_constant)
        except HTTPError as error:
            message = 'HTTPError: %s %s' % (
                getattr(error, 'code', ''),
                getattr(error, 'reason', str(error)),
            )
        except URLError as error:
            message = 'URLError: %s' % (error.reason if hasattr(error, 'reason') else str(error))
        except ValueError as error:
            message = 'JSON parse error: %s' % str(error)
        except Exception as error:
            message = 'Fetch error: %s' % str(error)
        logging.warning('json_fetch: endpoint %s: %s', endpoint['name'], message)
        return None

    def _flatten_payload(self, prefix, value, depth=3):
        if isinstance(value, bool):
            return {prefix: int(value)}
        if isinstance(value, (int, float)):
            if isinstance(value, float) and not math.isfinite(value):
                return {}
            return {prefix: value}
        if isinstance(value, dict) and depth > 0:
            out = {}
            for key, child in value.items():
                out.update(self._flatten_payload('%s_%s' % (prefix, re.sub(r'[^A-Za-z0-9_]', '_', '%s' % key)),
                                                  child, depth - 1))
            return out
        return {}  # strings, null, lists, too-deep values are skipped

    def run(self, config):
        try:
            endpoints = self._discover_endpoints(config)
        except Exception as error:
            return {'error': 'configuration error: %s' % str(error)}

        if not endpoints:
            return {'error': 'no endpoints configured in [json_fetch]; add url_<name> entries'}

        results = {}
        for endpoint in endpoints:
            payload = self._fetch_json(endpoint)
            if payload is None:
                results['%s_up' % endpoint['name']] = 0
                continue
            results['%s_up' % endpoint['name']] = 1
            metrics = self._flatten_payload(endpoint['name'], payload)
            if len(metrics) > MAX_METRICS_PER_ENDPOINT:
                logging.warning('json_fetch: endpoint %s: %d metrics, keeping first %d',
                                endpoint['name'], len(metrics), MAX_METRICS_PER_ENDPOINT)
                metrics = dict(sorted(metrics.items())[:MAX_METRICS_PER_ENDPOINT])
            results.update(metrics)

        return results


if __name__ == '__main__':
    Plugin().execute()
