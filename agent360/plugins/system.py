#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    import netifaces
except ImportError:
    netifaces = None
import os
import shlex
import platform
import socket
from subprocess import Popen, PIPE
import sys
import time
import psutil
import plugins
try:
    import distro
except ImportError:
    distro = None

def systemCommand(Command, newlines=True):
    Output = ""
    Error = ""
    try:
        if isinstance(Command, str):
            Command = shlex.split(Command)
        proc = Popen(Command, stdout=PIPE, stderr=PIPE)
        Output, Error = proc.communicate()
    except Exception:
        pass

    if isinstance(Output, bytes):
        Output = Output.decode("utf-8", "replace")
    if isinstance(Error, bytes):
        Error = Error.decode("utf-8", "replace")

    if Output:
        if newlines is True:
            Stdout = Output.split("\n")
        else:
            Stdout = Output
    else:
        Stdout = []
    if Error:
        Stderr = Error.split("\n")
    else:
        Stderr = []

    return (Stdout, Stderr)


def parse_cpuinfo_line(line):
    key, separator, value = line.partition(':')
    return key.strip(), value.strip() if separator else ""


def linux_hardware_memory():
    block_size = 0
    try:
        with open("/sys/devices/system/memory/block_size_bytes", "r") as f:
            block_size = int(f.readline().strip(), 16)

        memory = 0
        with os.scandir("/sys/devices/system/memory/") as it:
            for entry in it:
                if not entry.name.startswith("memory"):
                    continue
                with open(entry.path + "/state", "r") as f:
                    if "online" != f.readline().strip():
                        continue
                    else:
                        memory += block_size

        return memory
    except Exception:
        return 0


def ip_addresses():
    ip_list = {}
    ip_list['v4'] = {}
    ip_list['v6'] = {}
    if netifaces is None:
        try:
            addrs = psutil.net_if_addrs()
        except Exception:
            return ip_list

        for interface, addresses in addrs.items():
            for address in addresses:
                if address.family == socket.AF_INET:
                    if interface not in ip_list['v4']:
                        ip_list['v4'][interface] = []
                    ip_list['v4'][interface].append([{
                        'addr': address.address,
                        'netmask': address.netmask,
                        'broadcast': address.broadcast,
                        'ptp': getattr(address, 'ptp', None),
                    }])
                elif address.family == socket.AF_INET6:
                    if interface not in ip_list['v6']:
                        ip_list['v6'][interface] = []
                    ip_list['v6'][interface].append([{
                        'addr': address.address,
                        'netmask': address.netmask,
                        'broadcast': address.broadcast,
                        'ptp': getattr(address, 'ptp', None),
                    }])
        return ip_list
    for interface in netifaces.interfaces():
        link = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in link:
            if interface not in ip_list['v4']:
                ip_list['v4'][interface] = []
            ip_list['v4'][interface].append(link[netifaces.AF_INET])
        if netifaces.AF_INET6 in link:
            if interface not in ip_list['v6']:
                ip_list['v6'][interface] = []
            ip_list['v6'][interface].append(link[netifaces.AF_INET6])
    return ip_list


def windows_cpu_brand():
    brand = platform.processor()
    if brand:
        return brand

    brand = os.environ.get('PROCESSOR_IDENTIFIER', '')
    if brand:
        return brand

    try:
        output = systemCommand('wmic cpu get name', False)[0]
        if output:
            for line in output.split('\n'):
                line = line.strip()
                if line and line.lower() != 'name':
                    return line
    except Exception:
        pass

    return "Unknown CPU"


def linux_os_name():
    if distro is not None:
        try:
            return str(' '.join(distro.linux_distribution(full_distribution_name=True)))
        except Exception:
            pass

    try:
        return str(' '.join(platform.linux_distribution()))
    except Exception:
        return platform.platform()


class Plugin(plugins.BasePlugin):
    __name__ = 'system'

    def run(self, *unused):
        systeminfo = {}
        cpu = {}
        cpu['brand'] = "Unknown CPU"
        cpu['count'] = 0
        if os.path.isfile("/proc/cpuinfo"):
            with open('/proc/cpuinfo', 'r') as cpuinfo_file:
                for line in cpuinfo_file:
                    # Ignore the blank line separating the information between
                    # details about two processing units
                    if line.strip():
                        key, value = parse_cpuinfo_line(line)
                        if key == "model name":
                            cpu['brand'] = value
                        if key == "Processor":
                            cpu['brand'] = value
                        if key == "processor":
                            cpu['count'] = value
        if cpu['brand'] == "Unknown CPU":
            cpuinfo_output = systemCommand('lscpu', False)[0]
            if cpuinfo_output:
                for line in cpuinfo_output.split('\n'):
                    # Ignore the blank line separating the information between
                    # details about two processing units
                    if line.strip():
                        key, value = parse_cpuinfo_line(line)
                        if key == "Model name":
                            cpu['brand'] = value
                        if key == "Processor":
                            cpu['brand'] = value
                        if key == "CPU(s)":
                            cpu['count'] = value
        mem = psutil.virtual_memory().total
        if sys.platform == "linux" or sys.platform == "linux2":
            hw_mem = linux_hardware_memory()
            if hw_mem != 0:
                mem = hw_mem

            systeminfo['os'] = linux_os_name()
        elif sys.platform == "darwin":
            systeminfo['os'] = "Mac OS %s" % platform.mac_ver()[0]
            sysctl_output = systemCommand('sysctl machdep.cpu.brand_string', False)[0]
            if sysctl_output:
                brand_line = sysctl_output.split(': ', 1)
                if len(brand_line) > 1:
                    cpu['brand'] = brand_line[1]
            #cpu['count'] = systemCommand('sysctl hw.ncpu')
        elif sys.platform == "freebsd10" or sys.platform == "freebsd11":
            systeminfo['os'] = "FreeBSD %s" % platform.release()
            sysctl_output = systemCommand('sysctl hw.model', False)[0]
            if sysctl_output:
                brand_line = sysctl_output.split(': ', 1)
                if len(brand_line) > 1:
                    cpu['brand'] = brand_line[1]
            cpu_count_output = systemCommand('sysctl hw.ncpu', False)[0]
            if cpu_count_output:
                cpu['count'] = cpu_count_output.splitlines()[-1].strip()
        elif sys.platform == "win32":
            # https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
            if sys.getwindowsversion().build >= 22000:
                systeminfo['os'] = "{} {}".format(platform.uname()[0], 11)
            else:
                systeminfo['os'] = "{} {}".format(platform.uname()[0], platform.uname()[2])
            cpu['brand'] = windows_cpu_brand()
            cpu['count'] = psutil.cpu_count()
        systeminfo['cpu'] = cpu['brand']
        systeminfo['cores'] = cpu['count']
        systeminfo['memory'] = mem
        systeminfo['psutil'] = '.'.join(map(str, psutil.version_info))
        systeminfo['python_version'] = sys.version
        systeminfo['platform'] = platform.platform()
        systeminfo['uptime'] = int(time.time()-psutil.boot_time())
        systeminfo['ip_addresses'] = ip_addresses()
        systeminfo['hostname'] = platform.node()

        return systeminfo


if __name__ == '__main__':
    Plugin().execute()
