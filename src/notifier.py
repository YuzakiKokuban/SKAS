# Copyright 2026 YuzakiKokuban
# SPDX-License-Identifier: GPL-3.0-or-later

import requests
import json

def send_webhook(url, content):
    if not url:
        return
    
    headers = {'Content-Type': 'application/json'}
    payload = {
        'msgtype': 'text',
        'text': {'content': content},
        'title': 'SKAS Report',
        'body': content 
    }
    
    try:
        if 'dingtalk' in url:
            requests.post(url, json=payload)
        elif 'feishu' in url:
            requests.post(url, json=payload)
        else:
            requests.post(url, json={'content': content, 'message': content})
    except:
        pass