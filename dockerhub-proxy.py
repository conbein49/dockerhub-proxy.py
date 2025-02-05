import hashlib
import json
import re
from datetime import datetime, timedelta
from flask import Flask, request, Response
import requests
from cachetools import TTLCache

app = Flask(__name__)

# 模拟Cloudflare的缓存，使用TTL缓存（最大1000个条目，TTL 3600秒）
HAMMAL_CACHE = TTLCache(maxsize=1000, ttl=3600)
PROXY_HEADER_ALLOW_LIST = {'accept', 'user-agent', 'accept-encoding'}
DEFAULT_BACKEND_HOST = "https://registry-1.docker.io"
VALID_ACTION_NAMES = {"manifests", "blobs", "tags", "referrers"}

def parse_authenticate_str(authenticate_str):
    bearer = authenticate_str.split(maxsplit=1)
    if len(bearer) != 2 or bearer[0].lower() != "bearer":
        raise ValueError(f"Invalid Www-Authenticate {authenticate_str}")
    
    params = bearer[1].split(',')
    def get_param(name):
        for param in params:
            kv = param.split('=', 1)
            if len(kv) == 2 and kv[0].strip() == name:
                return re.sub(r'[\'"]', '', kv[1].strip())
        return ""
    
    return {
        'realm': get_param('realm'),
        'service': get_param('service'),
        'scope': get_param('scope')
    }

class TokenProvider:
    def __init__(self, username='', password=''):
        self.username = username
        self.password = password
    
    def authenticate_cache_key(self, www_authenticate):
        key_str = f"{self.username}:{self.password}/{www_authenticate['realm']}/{www_authenticate['service']}/{www_authenticate['scope']}"
        sha = hashlib.sha256(key_str.encode()).hexdigest()
        return f"token/{sha}"
    
    def token_from_cache(self, cache_key):
        return HAMMAL_CACHE.get(cache_key, None)
    
    def token_to_cache(self, cache_key, token):
        expires_in = token.get('expires_in', 3600)
        HAMMAL_CACHE[cache_key] = token
    
    def fetch_token(self, www_authenticate):
        url = www_authenticate['realm']
        params = {}
        if www_authenticate['service']:
            params['service'] = www_authenticate['service']
        if www_authenticate['scope']:
            params['scope'] = www_authenticate['scope']
        
        response = requests.get(url, params=params)
        if response.status_code != 200:
            raise Exception(f"Unable to fetch token from {url} status code {response.status_code}")
        
        data = response.json()
        return {
            'token': data.get('token'),
            'expires_in': data.get('expires_in', 3600)
        }
    
    def token(self, authenticate_str):
        www_authenticate = parse_authenticate_str(authenticate_str)
        cache_key = self.authenticate_cache_key(www_authenticate)
        cached_token = self.token_from_cache(cache_key)
        if cached_token:
            return cached_token
        
        token = self.fetch_token(www_authenticate)
        self.token_to_cache(cache_key, token)
        return token

class Backend:
    def __init__(self, host, token_provider=None):
        self.host = host
        self.token_provider = token_provider
    
    def proxy(self, pathname, headers):
        url = f"{self.host.rstrip('/')}/{pathname.lstrip('/')}"
        headers = {k: v for k, v in headers.items() if k.lower() in PROXY_HEADER_ALLOW_LIST}
        
        # 第一次请求
        response = requests.get(url, headers=headers, stream=True, allow_redirects=True)
        
        # 需要认证且提供token provider的情况
        if response.status_code == 401 and self.token_provider:
            authenticate_str = response.headers.get('Www-Authenticate')
            if authenticate_str:
                token = self.token_provider.token(authenticate_str)
                headers['Authorization'] = f"Bearer {token['token']}"
                response = requests.get(url, headers=headers, stream=True, allow_redirects=True)
        
        return response

def copy_proxy_headers(input_headers):
    return {k: v for k, v in input_headers.items() if k.lower() in PROXY_HEADER_ALLOW_LIST}

def org_name_from_path(pathname):
    # 示例实现，可根据实际需求修改
    return None

def host_by_org_name(org_name):
    return DEFAULT_BACKEND_HOST

def rewrite_path(org_name, pathname):
    parts = pathname.strip('/').split('/')
    if org_name is None and len(parts) >=4 and parts[2] in VALID_ACTION_NAMES:
        parts.insert(2, 'library')
    return '/' + '/'.join(parts)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handle_request(path):
    org_name = org_name_from_path(path)
    new_path = rewrite_path(org_name, path)
    host = host_by_org_name(org_name)
    
    token_provider = TokenProvider()
    backend = Backend(host, token_provider)
    
    headers = copy_proxy_headers(request.headers)
    response = backend.proxy(new_path, headers)
   
    # 流式响应处理
    def generate():
        chunk_size = 4096 * 1024  # 4MB分块
        for chunk in response.iter_content(chunk_size):
            yield chunk

    # 将响应返回给客户端
    excluded_headers = ['content-encoding', 'transfer-encoding']
    headers = [(k, v) for k, v in response.headers.items() if k.lower() not in excluded_headers]
    return Response(generate(), response.status_code, headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=18888)
