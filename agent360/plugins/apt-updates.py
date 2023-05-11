#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import plugins

class Plugin(plugins.BasePlugin):
    __name__ = 'apt-updates'

    def run(self, config):
        '''
        ubuntu/debian updates available from apt-get
        add to /etc/sudoers the following line:
        agent360 ALL=(ALL) NOPASSWD: /usr/bin/apt-get

        test by running:
        sudo -u agent360 agent360 test apt-updates

        Add to /etc/agent360.ini:
        [apt-updates]
        enabled = yes
        interval = 3600

        Optionally check if a reboot is required:
        checkreboot = true
        '''
        data = {}
        data['security'] = int(os.popen('sudo -n apt-get upgrade -s | grep Inst | grep security | wc -l').read())
        data['other'] = int(os.popen('sudo -n apt-get upgrade -s | grep Inst | grep -v security | wc -l').read())
        try:
            checkreboot = config.get('apt-updates', 'checkreboot')
            if os.path.exists('/var/run/reboot-required') and checkreboot == "true":
                data['Reboot Required'] = 'Yes'
            elif checkreboot == "true":
                data['Reboot Required'] = 'No'
        except Exception:
            pass
        return data

if __name__ == '__main__':
    Plugin().execute()
