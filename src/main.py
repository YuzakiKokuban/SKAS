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
    
    for idx, token in enumerate(tokens):
        mask_token = token[:4] + "***" + token[-4:]
        print(f"Processing Account {idx+1}: {mask_token}")
        client = SkylandClient(token)
        logs = client.run_sign(enable_games)
        for log in logs:
            print(log)
        all_logs.extend(logs)
        
    if webhook_url and all_logs:
        send_webhook(webhook_url, "\n".join(all_logs))

if __name__ == '__main__':
    main()