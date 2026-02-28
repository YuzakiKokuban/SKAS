# Copyright 2026 YuzakiKokuban
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
from client import SkylandClient
from notifier import send_webhook

def main():
    tokens = os.environ.get('SKYLAND_TOKEN', '').split(',')
    enable_games = os.environ.get('ENABLE_GAMES', 'arknights,endfield').split(',')
    webhook_url = os.environ.get('WEBHOOK_URL')
    
    tokens = [t.strip() for t in tokens if t.strip()]
    
    if not tokens:
        print("No tokens found in SKYLAND_TOKEN")
        sys.exit(1)
        
    all_logs = []
    global_success = True
    
    for idx, token in enumerate(tokens):
        mask_token = token[:4] + "***" + token[-4:]
        print(f"Processing Account {idx+1}: {mask_token}")
        client = SkylandClient(token)
        
        success, logs = client.run_sign(enable_games)
        if not success:
            global_success = False
            
        for log in logs:
            print(log)
        all_logs.extend(logs)
        
    if webhook_url and all_logs:
        send_webhook(webhook_url, "\n".join(all_logs))
        
    if not global_success:
        sys.exit(1)

if __name__ == '__main__':
    main()