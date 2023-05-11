#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import subprocess
import plugins
import json

class Plugin(plugins.BasePlugin):
    __name__ = 'fail2ban'

    def run(self, config):
        '''
        Monitor currently banned IP's, specify the fail2ban jail you want to monitor in /etc/agent360.ini
        
        Example:
        [fail2ban]
        enabled = yes
        jail = sshd
        
        Nota bene: agent360 requires sudo permission to access fail2ban-client 
        '''

        data = {}
        jail = config.get('fail2ban', 'jail').split(',')

        for nom in jail:
            data[nom] = {'count': os.popen('sudo /bin/fail2ban-client status '+ nom +' | egrep -i "Currently banned:.*"  | egrep -o "[0-9.]+"').read().rstrip()}

        return data

if __name__ == '__main__':
    Plugin().execute()
