# Copyright (c) 2026 YuzakiKokuban
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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