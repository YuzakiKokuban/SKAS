# Copyright 2026 YuzakiKokuban
# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import hmac
import json
import time
from urllib import parse
import requests
from security import get_d_id

APP_CODE = '4ca99fa6b56cc2ba'
GRANT_CODE_URL = "https://as.hypergryph.com/user/oauth2/v2/grant"
CRED_CODE_URL = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code"
BINDING_URL = "https://zonai.skland.com/api/v1/game/player/binding"
SIGN_URL_MAPPING = {
    'arknights': 'https://zonai.skland.com/api/v1/game/attendance',
    'endfield': 'https://zonai.skland.com/web/v1/game/endfield/attendance'
}

class SkylandClient:
    def __init__(self, token):
        self.token = token
        self.d_id = get_d_id()
        self.cred = None
        self.cred_token = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; SKAS/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36',
            'Accept-Encoding': 'gzip',
            'Connection': 'close',
            'dId': self.d_id,
            'X-Requested-With': 'com.hypergryph.skland'
        }

    def _generate_signature(self, path, body_or_query):
        t = str(int(time.time()) - 2)
        token_bytes = self.cred_token.encode('utf-8')
        header_ca = {
            'platform': '3',
            'timestamp': t,
            'dId': self.d_id,
            'vName': '1.0.0'
        }
        header_ca_str = json.dumps(header_ca, separators=(',', ':'))
        s = path + body_or_query + t + header_ca_str
        hex_s = hmac.new(token_bytes, s.encode('utf-8'), hashlib.sha256).hexdigest()
        md5 = hashlib.md5(hex_s.encode('utf-8')).hexdigest()
        return md5, header_ca

    def _get_sign_header(self, url, method, body=None):
        h = self.headers.copy()
        h['cred'] = self.cred
        p = parse.urlparse(url)
        if method.lower() == 'get':
            h['sign'], header_ca = self._generate_signature(p.path, p.query)
        else:
            h['sign'], header_ca = self._generate_signature(p.path, json.dumps(body) if body else '')
        h.update(header_ca)
        return h

    def login(self):
        resp_grant = requests.post(GRANT_CODE_URL, json={
            'appCode': APP_CODE,
            'token': self.token,
            'type': 0
        }, headers=self.headers).json()
        
        if resp_grant.get('status') != 0:
            raise Exception(f"OAuth Grant failed: {resp_grant.get('msg')}")
        
        grant_code = resp_grant['data']['code']
        
        resp_cred = requests.post(CRED_CODE_URL, json={
            'code': grant_code,
            'kind': 1
        }, headers=self.headers).json()

        if resp_cred.get('code') != 0:
            raise Exception(f"Get Cred failed: {resp_cred.get('message')}")
            
        self.cred = resp_cred['data']['cred']
        self.cred_token = resp_cred['data']['token']

    def get_bindings(self):
        headers = self._get_sign_header(BINDING_URL, 'get')
        resp = requests.get(BINDING_URL, headers=headers).json()
        if resp.get('code') != 0:
            raise Exception(f"Get bindings failed: {resp.get('message')}")
        
        bindings = []
        for app in resp['data']['list']:
            app_code = app.get('appCode')
            if app_code not in SIGN_URL_MAPPING:
                continue
            
            for item in app.get('bindingList'):
                if app_code == 'arknights':
                    item['appCode'] = app_code
                    item['display_name'] = item.get('nickName') or item.get('uid') or 'Unknown'
                    bindings.append(item)
                elif app_code == 'endfield':
                    if 'roles' in item:
                        for role in item['roles']:
                            role['appCode'] = app_code
                            role['display_name'] = role.get('nickname') or role.get('roleId') or 'Unknown'
                            role['channelName'] = item.get('channelName')
                            bindings.append(role)
        return bindings

    def sign_arknights(self, char):
        url = SIGN_URL_MAPPING['arknights']
        body = {'gameId': char['gameId'], 'uid': char['uid']}
        headers = self._get_sign_header(url, 'post', body)
        resp = requests.post(url, headers=headers, json=body).json()
        return resp

    def sign_endfield(self, char):
        url = SIGN_URL_MAPPING['endfield']
        headers = self._get_sign_header(url, 'post', None)
        headers['Content-Type'] = 'application/json'
        headers['sk-game-role'] = f"3_{char['roleId']}_{char['serverId']}"
        resp = requests.post(url, headers=headers).json()
        return resp

    def run_sign(self, enable_games=None):
        logs = []
        all_success = True
        try:
            self.login()
            chars = self.get_bindings()
            for char in chars:
                game = char['appCode']
                if enable_games and game not in enable_games:
                    continue
                
                name = char.get('display_name')
                
                try:
                    result = None
                    if game == 'arknights':
                        result = self.sign_arknights(char)
                    elif game == 'endfield':
                        result = self.sign_endfield(char)
                    
                    if result:
                        code = result.get('code')
                        msg = result.get('message') or 'OK'
                        
                        status = "FAIL"
                        if code == 0:
                            status = "SUCCESS"
                        elif "重复" in msg:
                            status = "INFO"
                            
                        if status == "FAIL":
                            all_success = False
                        
                        awards = ""
                        if result.get('data') and result['data'].get('awards'):
                            awards = " | 获得: " + ",".join([f"{a['resource']['name']}x{a['count']}" for a in result['data']['awards']])
                        
                        logs.append(f"[{game.upper()}] {name}: {status} - {msg}{awards}")
                except Exception as e:
                    all_success = False
                    logs.append(f"[{game.upper()}] {name}: ERROR - {str(e)}")
                    
        except Exception as e:
            all_success = False
            logs.append(f"Login/Init Error: {str(e)}")
            
        return all_success, logs