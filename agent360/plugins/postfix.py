#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import subprocess
import plugins
import re

class Plugin(plugins.BasePlugin):
    __name__ = 'postfix'

    def run(self, config):
        '''
        Monitoring of the Postfix MTA log and optionally the Postfix version and the mailqueue
        Dependency: Pflogsumm log analyzer, sudo access

        Example config for /etc/agent360.ini:
        [postfix]
        enabled = yes
        log = /var/log/mail.log
        pflogsumm = /usr/sbin/pflogsumm
        version = true
        queue = true
        '''
        data = {}
        maillog = config.get('postfix', 'log')
        pflbin = config.get('postfix', 'pflogsumm')
        pversion = config.get('postfix', 'version')
        mqueue = config.get('postfix', 'queue')

        output = os.popen('sudo ' + pflbin + ' -d today --detail 0 ' + maillog).read()

        for row in output.split("\n"):
            if re.search(r' +[0-9]+ +[a-z]{1}[a-z- ]+[a-z]', row):
                stat = re.findall(r'[a-z]{1}[a-z- ]+[a-z]', row)[0]
                num = re.findall(r'\b[0-9]*\b', row)[0]
                data[stat] =  int(num)


        if pversion == "true":
           data['meta'] = {'version': 'Postfix ' +  os.popen('sudo postconf -d | grep mail_version -m 1 | egrep -o "[0-9.]+"').read().rstrip()}

        if mqueue == "true":
           mqcommand = os.popen('sudo mailq | tail -n 1').read()
           if "empty" in mqcommand:
                data['queue'] = {'mails': 0 , 'size': 0 }
           else:
                data['queue'] = {'mails': re.findall(r'[0-9]+ Request', mqcommand)[0].replace(" Request", ""), 'size': re.findall(r'-- [0-9]+', mqcommand)[0].replace("-- ", "") }

        return data

if __name__ == '__main__':
    Plugin().execute()
