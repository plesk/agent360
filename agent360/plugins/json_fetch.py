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
"""

from __future__ import print_function, unicode_literals

import base64
import json

try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except Exception:
    from urllib2 import Request, urlopen, HTTPError, URLError

import plugins


DEFAULT_TIMEOUT = 10
DISABLED_VALUES = ('no', 'false', '0', 'off')
REQUEST_HEADERS = {
    'Accept': 'application/json',
    'User-Agent': 'agent360-json-fetch/2026.07',
}


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

            endpoint = {
                'name': endpoint_name,
                'url': config.get(section, option_name),
                'method': 'GET',
                'headers': {},
                'timeout': DEFAULT_TIMEOUT,
                'auth': None,
            }

            method_key = 'method_' + endpoint_name
            headers_key = 'headers_' + endpoint_name
            timeout_key = 'timeout_' + endpoint_name
            auth_key = 'auth_' + endpoint_name
            username_key = 'username_' + endpoint_name
            password_key = 'password_' + endpoint_name

            if config.has_option(section, method_key):
                endpoint['method'] = config.get(section, method_key).strip().upper() or 'GET'
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
        method = endpoint.get('method', 'GET')
        if method not in ('GET', 'POST'):
            try:
                request.get_method = lambda: method
            except Exception:
                pass

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
            response = urlopen(self._build_request(endpoint), timeout=endpoint['timeout'])
            payload = self._decode_payload(response.read())
            return json.loads(payload)
        except HTTPError as error:
            return {
                'error': 'HTTPError: %s %s' % (
                    getattr(error, 'code', ''),
                    getattr(error, 'reason', str(error)),
                )
            }
        except URLError as error:
            message = error.reason if hasattr(error, 'reason') else str(error)
            return {'error': 'URLError: %s' % message}
        except ValueError as error:
            return {'error': 'JSON parse error: %s' % str(error)}
        except Exception as error:
            return {'error': 'Fetch error: %s' % str(error)}

    def _flatten_payload(self, endpoint_name, payload):
        if isinstance(payload, dict):
            if len(payload) == 1:
                only_key = next(iter(payload))
                nested_value = payload[only_key]
                if isinstance(nested_value, dict):
                    return {
                        '{}_{}'.format(endpoint_name, child_key): child_value
                        for child_key, child_value in nested_value.items()
                    }
            return {
                '{}_{}'.format(endpoint_name, child_key): child_value
                for child_key, child_value in payload.items()
            }
        return {endpoint_name: payload}

    def run(self, config):
        try:
            endpoints = self._discover_endpoints(config)
        except Exception as error:
            return {'error': 'configuration error: %s' % str(error)}

        if not endpoints:
            return {'error': 'no endpoints configured in [json_fetch]; add url_<name> entries'}

        results = {}
        for endpoint in endpoints:
            url = endpoint.get('url')
            if not url:
                results[endpoint['name']] = {'error': 'missing url'}
                continue

            payload = self._fetch_json(endpoint)
            flattened = self._flatten_payload(endpoint['name'], payload)
            results.update(flattened)

        return results


if __name__ == '__main__':
    Plugin().execute()
