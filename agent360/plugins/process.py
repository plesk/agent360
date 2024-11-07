#!/usr/bin/env python
# -*- coding: utf-8 -*-
import psutil
import plugins
import sys
import re

class Plugin(plugins.BasePlugin):
    __name__ = 'process'

    def sanitize_command_line(self, cmdline):
        # Check if cmdline starts with a file path and separate it
        match = re.match(r'^(\S+)(\s+.*)?$', cmdline)
        if match:
            initial_path = match.group(1)
            remaining_cmdline = match.group(2) or ""
        else:
            initial_path = ""
            remaining_cmdline = cmdline

        # Redact sensitive information in the remaining command line (case-insensitive)
        remaining_cmdline = re.sub(r'(/[^ ]+)+', '/***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'(--(?:password|pass|pwd|token|secret|key|api-key|access-key|secret-key|client-secret|auth-key|auth-token)\s+\S+)', '--***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'(-p\s+\S+)', '-p ***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:password|pass|pwd|token|secret|key|api_key|access_key|client_secret|auth_key|auth_token)=\S+', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'(--port\s+\d+)', '--port ***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:DB_PASS|DB_USER|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SECRET_KEY|TOKEN|PASSWORD|USERNAME|API_KEY|PRIVATE_KEY|SSH_KEY|SSL_CERTIFICATE|SSL_KEY)\b=\S+', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(root|admin|cpanelsolr|user\d*)\b', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'(\S+\.(pem|crt|key|cert|csr|pfx|p12|ovpn|enc|asc|gpg))', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|known_hosts|authorized_keys|credentials|.env|docker-compose.yml)\b', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:jdbc|mysql|postgres|mongodb|redis|amqp|http|https|ftp|sftp|s3):\/\/\S+', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b(?:https?|ftp):\/\/(?:\S+\:\S+@)?(?:[a-zA-Z0-9.-]+\.\S+)', '***', remaining_cmdline, flags=re.IGNORECASE)
        remaining_cmdline = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '***', remaining_cmdline, flags=re.IGNORECASE)

        # Combine the initial path and the sanitized command line, then limit length
        sanitized_cmdline = (initial_path + remaining_cmdline).strip()
        if len(sanitized_cmdline) > 256:
            sanitized_cmdline = sanitized_cmdline[:253] + '...'

        return sanitized_cmdline

    def run(self, *unused):
        process = []
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=[
                    'pid', 'name', 'ppid', 'exe', 'cmdline', 'username',
                    'cpu_percent', 'memory_percent', 'io_counters'
                ])

                try:
                    # Sanitize and format the command line
                    pinfo['cmdline'] = self.sanitize_command_line(' '.join(pinfo['cmdline']).strip())
                except:
                    pass
                if sys.version_info < (3,):
                    pinfo['cmdline'] = unicode(pinfo['cmdline'], sys.getdefaultencoding(), errors="replace").strip()
                    pinfo['name'] = unicode(pinfo['name'], sys.getdefaultencoding(), errors="replace")
                    pinfo['username'] = unicode(pinfo['username'], sys.getdefaultencoding(), errors="replace")
                try:
                    pinfo['exe'] = unicode(pinfo['exe'], sys.getdefaultencoding(), errors="replace")
                except:
                    pass
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                pass
            except:
                pass
            else:
                process.append(pinfo)
        return process

if __name__ == '__main__':
    Plugin().execute()
