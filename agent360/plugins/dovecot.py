#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import subprocess
import plugins
import re

class Plugin(plugins.BasePlugin):
    __name__ = 'dovecot'

    def run(self, config):
        '''
        Returns active dovecot IMAP and POP3 session and the current version.
        Sudo permission to acces doveadm and dovecot commands are required.

        Example config for /etc/agent360.ini:
        [dovecot]
        enabled = yes
        '''
        data = {}
        output = os.popen('sudo doveadm who').read()
        output2 = os.popen('sudo dovecot --version').read()
        output3 = os.popen('sudo dovecot --hostdomain').read()
        imapsum = 0
        pop3sum = 0

        for row in output.split("\n"):
            if re.search(r'.*(imap|pop3).*', row):
                imapr = re.search(r' +([0-9]+) +imap +', row, re.IGNORECASE)
                popr = re.search(r' +([0-9]+) +pop3 +', row, re.IGNORECASE)
                if imapr is not None: imapsum = imapsum + int(imapr.group(1))
                if popr is not None: pop3sum = pop3sum + int(popr.group(1))


        data['imap'] = imapsum
        data['pop3'] = pop3sum
        data['meta'] = {'version': output2.strip(), 'hostdomain': output3.strip()}


        return data

if __name__ == '__main__':
    Plugin().execute()
