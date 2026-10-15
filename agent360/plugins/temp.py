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

Testing:
- agent360 test temp
"""

import plugins
import psutil
import sys
import json
import re

try:
    from urllib.request import Request, urlopen
except Exception:
    from urllib2 import Request, urlopen

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
                pass

        response = urlopen(request, timeout=3)
        try:
            payload = response.read().decode('utf-8', errors='replace')
        finally:
            try:
                response.close()
            except Exception:
                pass
        sensor_tree = json.loads(payload)

        def collect_temps(node):
            if not isinstance(node, dict):
                return

            value = node.get('Value')
            raw_value = node.get('RawValue')
            name = node.get('Text')
            sensor_type = node.get('Type')
            sensor_id = node.get('SensorId')

            if sensor_type == 'Temperature':
                source_value = raw_value if isinstance(raw_value, str) else value
                match = re.search(r'-?\d+(?:[\.,]\d+)?', source_value or '')
                parsed_value = match.group(0).replace(',', '.') if match else source_value
                try:
                    parsed_value = float(parsed_value)
                except Exception:
                    pass
                data[sensor_id or name or 'unknown'] = parsed_value

            children = node.get('Children') or []
            for child in children:
                collect_temps(child)

        collect_temps(sensor_tree)
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
                except Exception:
                    return 'Could not fetch temperature data from LibreHardwareMonitor webservice.'

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
            except Exception:
                return 'Could not fetch temperature data from OpenHardwareMonitor.'
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

                key = "%s-%s" % (device, label) if label else device
                if key in data:
                    key = "%s-%d" % (key, index)

                data[key] = current
        return data


if __name__ == '__main__':
    Plugin().execute()
