#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml
from yarl import URL
import sys
import netifaces
import socket
from rich.console import Console
from functools import cached_property

from typing import Dict, Literal

NotifyService = Literal["pushbullet"]

econsole = Console(stderr=True)

class WebServer:
    def __init__(self, base_url: str = None, port: int = None, path: str = None, local: bool = None, web_root: str | Path = None, cert_dir: str | Path = None):
        web_root = web_root or cert_dir  # cert_dir is depricated
        self.base_url: URL = base_url if not isinstance(base_url, str) else URL(base_url)
        self._port = port
        self._path = path
        self._local: bool = local
        self.web_root: Path = web_root if not web_root or isinstance(web_root, Path) else Path(web_root)

    @cached_property
    def url(self) -> URL | None:  # We allow this class to be instantiated with no values to avoid having to do multiple checks elsewhere
        if not self.base_url:
            return
        port_str = "" if self.base_url and self.base_url == self.port else f":{self.port}"
        return URL(f"{self.base_url}{port_str}/{self.path}")

    @cached_property
    def path(self) -> str:
        return "" if not self._path else self._path.lstrip("/")

    @cached_property
    def port(self) -> int:
        if self._port:
            return int(self._port)
        if not self.base_url:
            return 8080

        return self.base_url.port

    @cached_property
    def local(self) -> bool:
        if not self.base_url:
            return False

        return self._this_is_server(self.base_url, self._local)

    @property
    def valid(self) -> bool:
        return self.url is not None

    @staticmethod
    def _get_system_ip() -> str:
        pub_ip = None
        try:  # determine which IP is associated with the default gateway
            gw = netifaces.gateways()
            pub_iface = gw["default"][netifaces.AF_INET][1]
            pub_iface_addr = netifaces.ifaddresses(pub_iface)
            pub_ip = pub_iface_addr[netifaces.AF_INET][0]["addr"]
        except Exception as e:
            econsole.print(f"[bright_red]!![/]::warning:: Error Attempting to determine external IP: {e.__class__.__name__}")
            econsole.print("You can set webserver: local: to True or False to bypass this check.")
            # econsole.print(f"Exception in get_system_ip(): {e}")

        return pub_ip

    def _this_is_server(self, url: URL, local: bool | None = None) -> bool:
        if isinstance(local, bool):
            return local

        my_ip = self._get_system_ip()

        try:
            if my_ip and socket.gethostbyname(url.host) not in ["127.0.0.1", "::1", my_ip]:
                econsole.print(f"[dark_orange]:information:[/] webserver [cyan]{url.host}[/] defined in config does not appear to be this system.")
                return False
        except Exception as e:
            econsole.print(f"{e.__class__.__name__} Exception in Config.WebServer._this_is_server()\n{e}")

        return True

class Certificate:
    def __init__(self, p12: str, passphrase: str):
        self.p12 = p12
        self.passphrase = passphrase

    def __iter__(self):
        return iter(("p12", self.p12), ("passphrase", self.passphrase))

class Notify:
    def __init__(self, key: str, service: NotifyService = "pushbullet"):
        self.name = self.service = service.lower()
        self.key = key


class Config:
    def __init__(self):
        BASE_DIR = Path(__file__).parent.parent
        self.file: Path = BASE_DIR.joinpath('config.yaml')
        self.config: Dict[str, Any] = self.get_yaml_file(self.file) or {}
        self.DEBUG = self.config.get("debug", False)
        self.cppm_config: Dict[str, str | Dict[str, str]] = self.config.get("CPPM") or self.config.get("cppm", {})
        self.fqdn = self.cppm_config.get("fqdn")
        self.client_id = self.cppm_config.get("client_id")
        self.client_secret = self.cppm_config.get("client_secret")
        self.grant_type = self.cppm_config.get("grant_type", "client_credentials")
        self.username = self.cppm_config.get("username")
        self.password = self.cppm_config.get("password")
        if "webserver" not in self.cppm_config:
            self.webserver = None
        else:
            try:
                if "cert_dir" in self.cppm_config and "web_root" not in self.cppm_config["webserver"]:  # allow cert_dir under CPPM as was the case in prev versions
                    self.cppm_config["webserver"]["web_root"] = self.cppm_config["cert_dir"]
                self.webserver = WebServer(**self.cppm_config["webserver"])
            except TypeError as e:
                print(str(e))
                print("Config is missing required base_url under webserver")
                self.webserver = None

        self.certificates = self._get_certificates()

    @property
    def notify(self) -> Notify | None:
        _notify_config: Dict[str, str] = self.config.get("NOTIFY") or self.config.get("notify")
        if not _notify_config:
            return
        return Notify(_notify_config.get("api_key"), service=_notify_config.get("service"))

    def _get_certificates(self) -> Dict[str, Dict[str, str]]:
        if "certificates" in self.cppm_config:
            certs: Dict[str, Dict[str, str]] = self.cppm_config["certificates"]
            return {k: Certificate(**v) for k, v in certs.items()}
        if "https_cert_p12" in self.cppm_config:
            return {
                "https_rsa": {
                    "p12": self.cppm_config["https_cert_p12"],
                    "passphrase": self.cppm_config.get("https_cert_passphrase")
                }
            }

    @property
    def valid(self) -> bool:
        required = ["fqdn", "client_id", "client_secret"]
        if self.grant_type == "password":
            required += ["username", "password"]

        return None not in [getattr(self, field) for field in required]

    @property
    def valid_cert_sync(self) -> bool:
        if not self.valid:
            return self.valid
        conditions = [
            self.webserver and self.webserver.base_url,
            self.certificates
        ]
        return all(conditions)

    def __bool__(self):
        return len(self.config) > 0

    def __len__(self):
        return len(self.config)

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    @staticmethod
    def get_yaml_file(yaml_config: Path):
        '''Return dict from yaml file.'''
        if yaml_config.exists() and yaml_config.stat().st_size > 0:
            with yaml_config.open() as f:
                try:
                    return yaml.load(f, Loader=yaml.SafeLoader)
                except ValueError as e:
                    print(f'Unable to load configuration from {yaml_config}\n\t{e}', file=sys.stderr)
