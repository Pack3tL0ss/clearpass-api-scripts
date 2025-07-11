#!/usr/bin/env python3

import requests
import sys
# from common import config
from functools import partial
from typing import Literal, Dict, Any, Union
from yarl import URL
import pendulum
from functools import wraps

from .config import Config

print = partial(print, file=sys.stderr)
GrantType = Literal["client_credentials", "password"]
StrOrURL = Union[str, URL]

class ClearPassAuth(Config):
    def __init__(self):
        super().__init__()
        self.oath_base_url = URL(f"https://{self.fqdn}/api/oauth")
        self._token_response = self.get_access_token()
        self.access_token = self._token_response['access_token']
        self.token_type = self._token_response['token_type']
        self.token_expires_in = pendulum.duration(seconds=self._token_response['expires_in'])
        self.scope = self._token_response['scope']


    @property
    def headers(self) -> Dict[str, str]:
        _headers = {'Content-Type': 'application/json'}
        if hasattr(self, "access_token"):
            _headers = {**_headers, "Authorization": f"{self.token_type} {self.access_token}"}

        return _headers

    def build_url(func):
        @wraps(func)
        def wrapper(self, url: StrOrURL, *args, **kwargs):
            url = url if url.startswith("http") else self.oath_base_url / url.lstrip("/")
            return func(self, url, *args, **kwargs)

        return wrapper

    @build_url
    def get(self, url) -> Dict[str, Any]:
        """Generic GET request"""

        try:
            r = requests.get(url, headers=self.headers)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        return r.json()

    @build_url
    def post(self, url: str, payload: Dict[str, Any] = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Generic POST request"""

        headers = headers or self.headers

        try:
            r = requests.post(url, headers=headers, json=payload)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        return r.json()

    def get_access_token(self):
        """Get OAuth 2.0 access token with config from config.yaml"""

        url = f"https://{self.fqdn}/api/oauth"

        # headers = {'Content-Type': 'application/json'}

        # grant_type: client_credentials
        if self.grant_type == "client_credentials":
            payload = {'grant_type': self.grant_type, 'client_id': self.client_id, 'client_secret': self.client_secret}

        # grant_type: password   public client
        if self.grant_type == "password" and not self.client_secret:
            payload = {'grant_type': self.grant_type, 'username': self.username,
                    'password': self.password, 'client_id': self.client_id}

        # grant_type: password
        if self.grant_type == "password":
            payload = {'grant_type': self.grant_type, 'username': self.username, 'password': self.password,
                    'client_id': self.client_id, 'client_secret': self.client_secret}

        return self.post(url, payload=payload)

    def get_api_role(self):
        """Get the current ClearPass operator profile name"""

        url = f"https://{self.fqdn}/api/oauth/me"

        res = self.get(url)
        return res.get('info', res)

    def get_privs(self):
        """Get the current access privileges"""

        url = f"https://{self.fqdn}/api/oauth/privileges"

        res = self.get(url)
        return res.get('privileges', res)
