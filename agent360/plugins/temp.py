#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""agent360 temperature plugin.

Collects temperature metrics from system sensors.

Windows behavior:
- monitor = OpenHardwareMonitor (default): uses WMI namespace root\\OpenHardwareMonitor.
- monitor = LibreHardwareMonitor: reads JSON from a configurable webservice.

Optional config keys in the [temp] section (Windows only):
- monitor: OpenHardwareMonitor | LibreHardwareMonitor
- url: LibreHardwareMonitor JSON endpoint (default http://127.0.0.1:8085/data.json)
- username: optional basic-auth username for the webservice
- password: optional basic-auth password for the webservice

Example:
    [temp]
    monitor = LibreHardwareMonitor
    url = http://127.0.0.1:8085/data.json

Note: older LibreHardwareMonitor builds do not expose "Type" in data.json;
temperatures cannot be detected there and the plugin reports no data.

Testing:
- agent360 test temp
"""

import plugins
import psutil
import sys
import json
import logging
import re

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)

class Plugin(plugins.BasePlugin):
    __name__ = 'temp'

    def _get_config_value(self, config, key, default=None):
        if not config:
            return default
        try:
            if config.has_section(self.__name__) and config.has_option(self.__name__, key):
                return config.get(self.__name__, key)
        except Exception:
            return default
        return default

    def _get_monitor_backend(self, config):
        backend = self._get_config_value(config, 'monitor', 'OpenHardwareMonitor')
        if not backend:
            return 'openhardwaremonitor'
        return str(backend).strip().lower()

    def _fetch_lhm_temperatures(self, config):
        data = {}
        url = self._get_config_value(config, 'url', 'http://127.0.0.1:8085/data.json')
        username = self._get_config_value(config, 'username')
        password = self._get_config_value(config, 'password')

        request = Request(url)
        if username and password:
            try:
                import base64
                token = ('%s:%s' % (username, password)).encode('utf-8')
                auth_header = base64.b64encode(token).decode('ascii')
                request.add_header('Authorization', 'Basic ' + auth_header)
            except Exception:
                logging.exception('temp: could not build basic-auth header')

        response = urlopen(request, timeout=3)
        try:
            payload = response.read().decode('utf-8', errors='replace')
        finally:
            try:
                response.close()
            except Exception:
                pass
        sensor_tree = json.loads(payload)

        def parse_temperature(*candidates):
            for candidate in candidates:
                if isinstance(candidate, (int, float)):
                    return float(candidate)
                if isinstance(candidate, string_types):
                    match = re.search(r'-?\d+(?:[\.,]\d+)?', candidate)
                    if match:
                        return float(match.group(0).replace(',', '.'))
            return None

        def collect_temps(node, path):
            if not isinstance(node, dict):
                return

            name = node.get('Text') or ''

            if node.get('Type') == 'Temperature':
                temperature = parse_temperature(node.get('RawValue'), node.get('Value'))
                if temperature is not None:
                    sensor_id = node.get('SensorId')
                    if sensor_id:
                        # same normalisation as the OpenHardwareMonitor backend
                        key = sensor_id.replace('/', '-').strip('-')
                    else:
                        # no SensorId (older versions): use the tree path so
                        # sensors with equal names on different hardware don't collide
                        key = '-'.join([p for p in path + [name] if p]) or 'unknown'
                    data[key] = temperature

            for child in node.get('Children') or []:
                collect_temps(child, path + [name])

        collect_temps(sensor_tree, [])
        return data

    def run(self, config=None, *unused):
        data = {}

        if sys.platform == "win32":
            backend = self._get_monitor_backend(config)

            if backend == 'librehardwaremonitor':
                try:
                    data = self._fetch_lhm_temperatures(config)
                    if not data:
                        return 'LibreHardwareMonitor returned no temperature data.'
                    return data
                except Exception as e:
                    logging.debug('temp: LibreHardwareMonitor error', exc_info=True)
                    return 'Could not fetch temperature data from LibreHardwareMonitor webservice: %s' % e

            try:
                import wmi
            except Exception:
                return 'wmi module not installed for OpenHardwareMonitor backend.'

            try:
                w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
                temperature_infos = w.Sensor()
                for sensor in temperature_infos:
                    if sensor.SensorType == u'Temperature':
                        data[sensor.Parent.replace('/', '-').strip('-')] = sensor.Value
                return data
            except Exception as e:
                logging.debug('temp: OpenHardwareMonitor error', exc_info=True)
                return 'Could not fetch temperature data from OpenHardwareMonitor: %s' % e
        if not hasattr(psutil, "sensors_temperatures"):
            return "platform not supported"

        try:
            temps = psutil.sensors_temperatures()
        except Exception:
            return "can't read any temperature"

        for device, readings in (temps or {}).items():
            if not readings:
                continue

            for index, reading in enumerate(readings, 1):
                if hasattr(reading, "label"):
                    label = reading.label or ""
                    current = reading.current
                else:
                    label = reading[0] if len(reading) > 0 else ""
                    current = reading[1] if len(reading) > 1 else None

                if current is None:
                    continue

                try:
                    current = float(current)
                except Exception:
                    continue

                # Keep the historical key (label, or device name when there is
                # no label) so existing metric series are not renamed; only
                # disambiguate when it would overwrite another reading.
                key = label or device
                if key in data:
                    key = "%s-%s" % (device, label) if label else "%s-%d" % (device, index)
                if key in data:
                    key = "%s-%d" % (key, index)

                data[key] = current
        return data


if __name__ == '__main__':
    Plugin().execute()
