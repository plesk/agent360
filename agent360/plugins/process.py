#!/usr/bin/env python
# -*- coding: utf-8 -*-
import psutil
import plugins
import sys
import re

class Plugin(plugins.BasePlugin):
    __name__ = 'process'

    # Optional config keys in [process]:
    # - disable_filtering = yes to bypass all cmdline filtering/redaction.
    # - additional_filter_patterns = comma-separated literal patterns with '*' wildcard
    #   for extra redaction (for example: mypassword*,token=*).
   

    def _get_additional_filter_wildcards(self, config):
        if config is None:
            return []

        try:
            value = config.get(self.__name__, 'additional_filter_patterns')
        except Exception:
            value = ''

        if not value:
            return []

        patterns = []
        for pattern in str(value).split(','):
            pattern = pattern.strip()
            if pattern:
                patterns.append(pattern)
        return patterns

    def _compile_wildcard_regexes(self, wildcard_patterns):
        wildcard_regexes = []
        for wildcard_pattern in wildcard_patterns:
            # Treat user input as literal text; only '*' is wildcard.
            # '*' expands to any characters, including spaces.
            wildcard_regex = re.escape(wildcard_pattern)
            wildcard_regex = wildcard_regex.replace(r'\*', r'.*')
            wildcard_regexes.append(re.compile(wildcard_regex, re.IGNORECASE))
        return wildcard_regexes

    def _is_filtering_disabled(self, config):
        if config is None:
            return False

        try:
            value = config.get(self.__name__, 'disable_filtering')
        except Exception:
            value = 'no'

        return str(value).strip().lower() in ('1', 'true', 'yes', 'on')

    def sanitize_command_line(self, cmdline, additional_filter_wildcard_regexes=None):
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

        if additional_filter_wildcard_regexes:
            for wildcard_regex in additional_filter_wildcard_regexes:
                try:
                    # Optional user-defined wildcard rules for extra redaction.
                    remaining_cmdline = wildcard_regex.sub('***', remaining_cmdline)
                except Exception:
                    pass

        # Combine the initial path and the sanitized command line, then limit length
        sanitized_cmdline = (initial_path + remaining_cmdline).strip()
        if len(sanitized_cmdline) > 256:
            sanitized_cmdline = sanitized_cmdline[:253] + '...'

        return sanitized_cmdline

    def run(self, config=None, *unused):
        process = []
        filtering_disabled = self._is_filtering_disabled(config)
        additional_filter_wildcards = self._get_additional_filter_wildcards(config)
        additional_filter_wildcard_regexes = self._compile_wildcard_regexes(additional_filter_wildcards)
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=[
                    'pid', 'name', 'ppid', 'exe', 'cmdline', 'username',
                    'cpu_percent', 'memory_percent', 'io_counters'
                ])

                try:
                    raw_cmdline = ' '.join(pinfo['cmdline']).strip()
                    if filtering_disabled:
                        pinfo['cmdline'] = raw_cmdline
                    else:
                        # Sanitize and format the command line
                        pinfo['cmdline'] = self.sanitize_command_line(raw_cmdline, additional_filter_wildcard_regexes)
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
