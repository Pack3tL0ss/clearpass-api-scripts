#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
#
# Version: 2025-9.3
#
from __future__ import annotations

import datetime
import socket
import sys
import threading
import zoneinfo
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import environ as env
from pathlib import Path, PurePath
from typing import Any, Dict, Tuple

import netifaces
import pendulum
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from rich.console import Console
from yarl import URL

from common import cppmauth, log

cppm_config: Dict[str, Any] = cppmauth.config.get("CPPM", {})

cppm_args = (cppmauth.clearpass_fqdn, cppmauth.token_type, cppmauth.access_token)
cert_p12 = cppm_config.get("https_cert_p12")
cert_passphrase = cppm_config.get("https_cert_passphrase")
cert_dir = cppm_config.get("cert_dir")

NOTIFY: Dict[str, str] = cppmauth.config.get("NOTIFY", {})
pb_key = NOTIFY.get("api_key")


# certificate expiry looks like 'Apr 04, 2025 14:04:11 CDT'
# but pendulum format specifier for timezone (zz) doesn't like some of the values "CDT, EDT..."
# are not valid.  Below is used to get around this swapping for valid values from tz database
def get_timezone_from_abbr(abbr) ->zoneinfo.ZoneInfo | str:
    """Convert timezone abbreviation to a valid ZoneInfo timezone string."""
    now = datetime.datetime.now()
    for tz in zoneinfo.available_timezones():
        timezone = zoneinfo.ZoneInfo(key=tz)
        # Using the timezone object, get the name of the timezone from datetime
        tz_name = now.astimezone(timezone).tzname()
        if tz_name == abbr:
            return timezone # Pendulum can handle a ZoneInfo timezone object, or a string

    return abbr  # Fallback to the original, pendulum might be able to handle it, who knows?


class CpHandler(BaseHTTPRequestHandler):
    CERTNAME: str = None
    passphrase: str = None

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pkcs12")
        self.end_headers()
        p = Path(PurePath(cert_dir, cert_p12))
        self.wfile.write(p.read_bytes())
        log.info(f"Sending {p.name}")
        return


def _get_system_ip() -> str:
    pub_ip = None
    try:  # determine which IP is associated with the default gateway
        gw = netifaces.gateways()
        pub_iface = gw["default"][netifaces.AF_INET][1]
        pub_iface_addr = netifaces.ifaddresses(pub_iface)
        pub_ip = pub_iface_addr[netifaces.AF_INET][0]["addr"]
    except Exception as e:
        log.exception(f"Exception in get_system_ip(): {e}")
        c = Console()
        c.print(f"[bright_red]!![/]::warning:: Error Attempting to determine external IP: {e.__class__.__name__}")
        c.print("You can set webserver: local: to True or False to bypass this check.")

    return pub_ip

def _this_is_server(full_url: URL) -> bool:
    config_is_local = cppm_config.get("webserver", {}).get("local")
    if isinstance(config_is_local, bool):
        return config_is_local

    my_ip = _get_system_ip()

    try:
        if my_ip and socket.gethostbyname(full_url.host) not in ["127.0.0.1", "::1", my_ip]:
            return False
    except Exception as e:
        log.exception(f"{e.__class__.__name__} Exception in this_is_server()\n{e}")

    return True

def load_pb():
    if pb_key:
        try:
            from common.notify import Push
        except ImportError:
            log.error("An API key for PushBullet was provided but the PushBullet Module was not found")
            log.error("\t Likely Need to 'venv/bin/python3 -m pip install pushbullet.py'")
            return

        return Push(pb_key).sendpush


def verify_config():
    values = [cert_p12, cert_passphrase, cppm_config.get("webserver", {}).get("base_url")]
    keys = ["https_cert_p12", "https_cert_passphrase", "webserver:base_url"]
    if None in values:
        missing = [k for k, v in zip(keys, values) if v is None]
        log.fatal(f"config is missing a required fields ({', '.join(missing)}), please see the example config")
        exit(1)
    elif NOTIFY and pb_key and not NOTIFY.get("service"):
        log.info("No 'service' specified for notifications, assuming PushBullet")


def get_le_cert_from_external(webserver_full_url: str):
    try:
        r = requests.get(webserver_full_url)
        if not r.ok:
            print(f"Failed to get cert from external webserver {webserver_full_url}")
            sys.exit(1)
        else:
            return r.content
    except Exception as e:
        log.exception(f"Exception occured while getting current LE cert from {webserver_full_url}. {e.__class__.__name__}", show=True)
        log.exception(e)
        sys.exit(1)


def verify_cert(this_is_server: bool = True, webserver_full_url: str = None):
    p = Path(PurePath(cert_dir or Path().home(), cert_p12))
    if p.exists():
        pb = p.read_bytes()
    elif not this_is_server:
        pb = get_le_cert_from_external(webserver_full_url)
    else:
        log.fatal(f"{p.name} Not Found")
        sys.exit(1)

    le_p12 = pkcs12.load_key_and_certificates(pb, cert_passphrase.encode("UTF-8"), backend=default_backend())
    le_cert = le_p12[1]
    le_exp = le_cert.not_valid_after_utc

    return le_exp


def get_server_ids(clearpass_fqdn: str, token_type: str, access_token: str) -> list:
    """Get list of server ids"""

    url = "https://" + clearpass_fqdn + "/api/cluster/server"

    headers = {"Content-Type": "application/json", "Authorization": "{} {}".format(token_type, access_token)}

    try:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
    except Exception as e:
        log.error(f"exception: {e}")
        exit(1)

    servers = r.json().get("_embedded", {}).get("items", {})
    return {svr.get("name"): svr.get("server_uuid") for svr in servers}


def start_webserver(port: int = 8080):
    httpd = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if s.connect_ex(("127.0.0.1", port)) == 0:
        log.warning(f"Something Appears to be Using port {port}")
    else:
        log.info(f"Starting WebServer on Port {port}")
        handler = CpHandler
        handler.CERTNAME = cert_p12
        handler.passphrase = cert_passphrase
        httpd = HTTPServer(("", port), CpHandler)
        httpd.allow_reuse_address = True
        threading.Thread(target=httpd.serve_forever, args=[2], name="webserver").start()

    return httpd


def put_https_cert(
    webserver_url: str,
    servers: dict,
    le_exp: datetime.datetime,
    cppm_fqdn: str,
    token_type: str,
    access_token: str,
    server_version: float,
) -> list:
    """Update https Certificate to CPPM"""

    svc = "HTTPS" if int(server_version[1]) < 10 else "HTTPS(RSA)"
    if "--usage" in sys.argv:
        try:
            override_svc = sys.argv[sys.argv.index("--usage") + 1]
        except IndexError:
            econsole = Console(stderr=True)
            econsole.print("[red]Error[/]:  Missing argument after [cyan]--usage[/] :triangular_flag:")
            sys.exit(1)
    else:
        override_svc = cppm_config.get("cert_usage") or env.get("CPPM_CERT_USAGE")

    svc = override_svc or svc
    urls = [(svr, f"https://{cppm_fqdn}/api/server-cert/name/{uuid}/{svc}") for svr, uuid in servers.items()]

    payload = {
        "pkcs12_file_url": webserver_url,
        "pkcs12_passphrase": cert_passphrase,
    }

    headers = {"Content-Type": "application/json", "Authorization": f"{token_type} {access_token}"}

    _res = []
    for url in urls:
        try:
            r = requests.get(url[1], headers=headers)
            if r.ok:
                rdict = r.json()
                this_exp = rdict.get("expiry_date")  # looks like 'Apr 04, 2025 14:04:11 CDT'
                tzstr = " ".join(this_exp.split()[-1:])  # zz format specifier doesn't work so need to split tz out.  See https://github.com/python-pendulum/pendulum/issues/279
                tzstr = get_timezone_from_abbr(tzstr)
                this_exp = pendulum.from_format(" ".join(this_exp.split()[0:-1]), "MMM DD, YYYY HH:mm:ss", tz=tzstr)
                this_exp = this_exp.in_timezone("UTC")  # covert to UTC to match tz of le_exp
                diff = le_exp - this_exp
                is_self_signed = True if rdict.get("subject", "subject") == rdict.get("issued_by", "") else False
                if diff.days > 0 or is_self_signed:
                    if is_self_signed:
                        log.info(f"Updating {url[0]} certificate as the current cert is self signed.")

                    # tell cppm to download new cert
                    r = requests.put(url[1], json=payload, headers=headers, verify=False)
                    _res.append((url[0], "updated") if r.status_code == 200 else (url[0], "error"))
                    if r.ok:
                        log.info(f"PUT:OK:{url[0]}:{r.status_code}:{r.reason}")
                    else:
                        _msg = "\n".join([f"\t{k}: {v}" for k, v in r.json().items() if v])
                        log.error(f"PUT:ERROR:{url[0]}\n{_msg}")
                else:
                    _msg = f"LE cert has same expiration as {url[0]} {svc} cert No Update performed"
                    _res.append((url[0], "same"))
                    log.info(_msg)
            else:
                _res.append((url[0], "error"))
                _msg = f"GET: {r.status_code}:{r.reason}"
                log.error(_msg)
        except Exception as e:
            _msg = "Exception: \n{}".format("\n".join([f"\t{k}: {v}" for k, v in e.__dict__.items()]))
            log.exception(_msg)

    return _res


def get_server_version(clearpass_fqdn: str, token_type: str, access_token: str) -> list:
    """Get server version"""

    url = "https://" + clearpass_fqdn + "/api/server/version"

    headers = {"Content-Type": "application/json", "Authorization": "{} {}".format(token_type, access_token)}

    try:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
    except Exception as e:
        log.error(f"exception: {e}")
        exit(1)

    try:
        return r.json().get("cppm_version").split(".")[0:2]
    except Exception as e:
        print(e)
        log.error(e)
        exit(1)


def get_webserver_info() -> Tuple[URL, int]:
    webserver_config = cppm_config.get("webserver", {})
    webserver_base = webserver_config.get("base_url")
    webserver_port = webserver_config.get("port", 8080)
    webserver_path = webserver_config.get("path", "")

    webserver_port = int(webserver_port)
    port_str = "" if not webserver_port else f":{webserver_port}"
    full_url = URL(f"{webserver_base}{port_str}/{webserver_path}/{cert_p12}".replace(f"//{cert_p12}", f"/{cert_p12}"))

    return full_url, webserver_port


if __name__ == "__main__":
    httpd = None
    c = Console()
    # config and file verification
    verify_config()

    # get server uuids from publisher
    cluster_servers = get_server_ids(*cppm_args)

    webserver_full_url, webserver_port = get_webserver_info()
    this_is_server = _this_is_server(webserver_full_url)

    # Start webserver to provide certs to CPPM
    if this_is_server:
        httpd = start_webserver(port=webserver_port)
        if "--serve-only" in sys.argv:
            try:
                c.print(":information:  webserver only mode.  CTRL-C to stop webserver")
                while True:
                    import time
                    time.sleep(3)
            except KeyboardInterrupt:
                log.info("Stopping WebServer")
                httpd.shutdown()
                sys.exit(0)
    else:
        if cppm_config.get("webserver", {}).get("local") is None:
            c.print(f"[dark_orange]:warning:[/] webserver [cyan]{webserver_full_url}[/] defined in config does not appear to be this system.")
        c.print("skipping web_server startup, based on config.")

    le_exp = verify_cert(this_is_server, webserver_full_url=str(webserver_full_url))

    # get server version
    cppm_ver = get_server_version(*cppm_args)

    # push certs
    res = put_https_cert(str(webserver_full_url), cluster_servers, le_exp, *cppm_args, server_version=cppm_ver)

    if httpd:
        log.info("Stopping WebServer")
        httpd.shutdown()

    if "no-push" not in str(sys.argv):
        try:
            push = load_pb()
            if push and [r[1] for r in res if r[1] != "same"]:
                res_str = "\n".join([f"{svr}: {result}" for svr, result in res])
                push_res = push("ClearPass https Cert Update", res_str)
                log.debug(f"Push Response:\n{push_res}")
        except Exception as e:
            log.exception(f"PushBullet Exception: {e}")
