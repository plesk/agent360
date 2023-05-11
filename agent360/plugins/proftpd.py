#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import plugins
import json

class Plugin(plugins.BasePlugin):
    __name__ = 'proftpd'

    def run(self, config):
        '''
        Current acitive ProFTPD sessions
        '''
        data = {}
        result = os.popen('/bin/ftpwho -o json').read()
        cnt = 0
        uploading = 0
        idle = 0
        rawdata=json.loads(result)
        for item in rawdata['connections']:
              if item['pid']: cnt += 1
              try:
                  if item['uploading'] == True: uploading += 1
              except Exception:
                  pass
              try:
                  if item['idling'] == True: idle += 1
              except Exception:
                  pass
        data['connections'] = cnt
        data['uploading'] = uploading
        data['idle'] = idle
        data['server_type'] = rawdata['server']['server_type']
        data['pid'] =  "PID " + str(rawdata['server']['pid'])
        updt = rawdata['server']['started_ms']
        data['uptime'] = {'ms': updt}
        return data

if __name__ == '__main__':
    Plugin().execute()
