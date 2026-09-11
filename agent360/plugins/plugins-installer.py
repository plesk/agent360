#!/usr/bin/env python
# -*- coding: utf-8 -*-
import plugins
import os
import glob
import sys
import ssl
import certifi
import logging
import json
import time
import threading
import subprocess
from pprint import pprint

if sys.version_info >= (3,):
    import http.client
    import configparser
    try:
        from past.builtins import basestring
    except ImportError:
        basestring = str
else:
    import httplib
    import ConfigParser as configparser


config_path = os.path.join('/etc', 'agent360-custom.ini')

if os.name == 'nt':
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'agent360-custom.ini')

class Plugin(plugins.BasePlugin):
    __name__ = 'plugins-installer'

    # guard flags to prevent multiple updater threads
    _updater_started = False
    _lock = threading.Lock()

    def run(self, config):
        self.config = config

        # ensure only one background updater thread
        with Plugin._lock:
            if not Plugin._updater_started:
                Plugin._updater_started = True
                t = threading.Thread(
                    target=self._periodic_updater,
                    name="PluginUpdaterThread",
                    daemon=True
                )
                t.start()

        return self._get_plugins(config)

    def _periodic_updater(self):
        while True:
            try:
                updated = self._update_plugins_from_backend()
                if updated:
                    logging.info("Plugins updated, restarting agent")
                    self._restart_agent()
            except Exception as e:
                logging.error("Error in periodic plugin update: %s", e)

            try:
                interval = self.config.getint(__name__, 'interval')
                interval = max(interval, 60)
            except Exception:
                interval = 1800  # default 30 minutes
            time.sleep(interval)


    def _restart_agent(self):
        pid = os.fork()
        if pid == 0:
            time.sleep(5)  # Wait 5 seconds to let agent360 complete plugin execution
            try:
                subprocess.run(['systemctl', 'restart', 'agent360'], check=True)
            except Exception as e:
                logging.error('Failed to restart agent360: %s', e)
            os._exit(0)

    def _update_plugins_from_backend(self, proto='https'):
        server = self.config.get('agent', 'server')
        user = self.config.get('agent', 'user')
        updated = False

        body = {'userId': user, 'serverId': server}
        try:
            connection = self._get_connection(proto)
            connection.request('POST', '/plugin-manager/get-backend-state',  str(json.dumps(body)).encode())
            response = connection.getresponse()

            if response.status == 200:
                logging.debug('Successful response: %s', response.status)
            else:
                raise ValueError('Unsuccessful response: %s' % response.status)

            backend_config = json.loads(response.read().decode())

            for plugin in backend_config:
                for c in plugin['config']:
                    updated = True
                    self._set_plugin_configuration(plugin['id'], c, plugin['config'][c])
        except Exception as e:
            logging.error('Failed to get plugins state: %s', e)
            return False
        return updated

    def _get_connection(self, proto='https'):
        api_host = self.config.get('data', 'hello_api_host')
        if (proto == 'https'):
            ctx = ssl.create_default_context(cafile=certifi.where())
            if sys.version_info >= (3,):
                return http.client.HTTPSConnection(api_host, context=ctx, timeout=15)
            else:
                return httplib.HTTPSConnection(api_host, context=ctx, timeout=15)
        else:
            if sys.version_info >= (3,):
                return http.client.HTTPConnection(api_host, timeout=15)
            else:
                return httplib.HTTPConnection(api_host, timeout=15)

    def _get_plugins_path(self):
        if os.name == 'nt':
            return os.path.expandvars(self.config.get('agent', 'plugins'))
        else:
            return self.config.get('agent', 'plugins')

    def _get_plugins(self, config):
        plugins_path = self._get_plugins_path()
        plugins = {}
        for filename in glob.glob(os.path.join(plugins_path, '*.py')):
            plugin_name = self._plugin_name(filename)
            if plugin_name == 'plugins' or plugin_name == '__init__':
                continue
            self._config_section_create(plugin_name)
            plugins[plugin_name] =  self._get_config_section_properties(config, plugin_name)

        return plugins

    def _plugin_name(self, plugin):
        if isinstance(plugin, basestring):
            basename = os.path.basename(plugin)
            return os.path.splitext(basename)[0]
        else:
            return plugin.__name__

    def _config_section_create(self, section):
        if not self.config.has_section(section):
            self.config.add_section(section)

    def _get_config_section_properties(self, config, section_name):
        # Exclude parent configuration
        excluded_keys = ['api_host', 'api_path', 'interval', 'log_file', 'log_file_mode',
                         'logging_level', 'max_cached_collections', 'max_data_age', 'max_data_span',
                         'plugins', 'server', 'subprocess', 'threads', 'ttl', 'user']
        if section_name in config:
            properties = {
                key: config[section_name][key]
                for key in config.options(section_name)
                if key in config[section_name] and key not in excluded_keys
            }
            return dict(properties)
        else:
            return {}

    def _set_plugin_configuration(self, plugin, key, value):
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(config_path)

        if plugin not in config.sections():
            config.add_section(plugin)

        config.set(plugin, key, value)

        with open(config_path, 'w') as file:
            config.write(file)

if __name__ == '__main__':
    Plugin().execute()
