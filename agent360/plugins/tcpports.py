#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import plugins


class Plugin(plugins.BasePlugin):
    __name__ = 'tcpports'

    def run(self, config):
        '''
        Checks if TCP ports are open.
        '''
        def is_port_open(host, port, timeout):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)  # Timeout for the connection attempt
            try:
                sock.connect((host, port))
                sock.close()
                return 1
            except socket.error:
                return 0

        results = dict()

        # Parse the config for the host-port pairs to check
        host_ports = config.get(__name__, 'host_ports').split(',')
        timeout = float(config.get(__name__, 'timeout'))  # Timeout for the connection attempt

        for host_port in host_ports:
            host, port = host_port.split(':')
            port = int(port)
            results[host_port] = {'available': is_port_open(host, port, timeout)}

        return results


if __name__ == '__main__':
    Plugin().execute()
