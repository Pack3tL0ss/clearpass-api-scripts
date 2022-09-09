#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
#
# Version: 2020-1.1
#

import datetime
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePath
from typing import Tuple
from rich.console import Console

import requests
import netifaces
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12

from common import cppmauth, log
cppm_config = cppmauth.config.get("CPPM", {})

cppm_args = (cppmauth.clearpass_fqdn, cppmauth.token_type, cppmauth.access_token)
cert_p12 = cppm_config.get("https_cert_p12")
cert_passphrase = cppm_config.get("https_cert_passphrase")
cert_dir = cppm_config.get("cert_dir")

NOTIFY = cppmauth.config.get("NOTIFY", {})
pb_key = NOTIFY.get("api_key")


class CpHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pkcs12")
        self.end_headers()
        p = Path(PurePath(cert_dir, cert_p12))
        self.wfile.write(p.read_bytes())
        log.info(f"Sending {p.name}")
        return


def get_system_ip() -> str:
    try:
        gw = netifaces.gateways()
        pub_iface = gw["default"][netifaces.AF_INET][1]
        pub_iface_addr = netifaces.ifaddresses(pub_iface)
        pub_ip = pub_iface_addr[netifaces.AF_INET][0]["addr"]
    except Exception as e:
        log.exception(f"Exception in get_system_ip(): {e}")
        c = Console()
        c.print(f"[bright_red]!![/]::warning:: Error Attempting to determine external IP: {e.__class__.__name__}")
        c.print("You can manually specify the webserver in the config [cyan]webserver: <ip address of fqdn>[/]")
        c.print("exiting...")
        sys.exit(1)

    return pub_ip


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
    if None in [cert_p12, cert_passphrase, cert_dir, cppm_config.get("webserver", {}).get("base_url"), cppm_config.get("webserver", {}).get("port")]:
        log.fatal("config is missing a required variable, please see the example config")
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
    p = Path(PurePath(cert_dir, cert_p12))
    if p.exists():
        pb = p.read_bytes()
    elif not this_is_server:
        pb = get_le_cert_from_external(webserver_full_url)
    else:
        log.fatal(f"{p.name} Not Found")
        sys.exit(1)


    le_p12 = pkcs12.load_key_and_certificates(
        pb,
        cert_passphrase.encode("UTF-8"),
        backend=default_backend()
        )
    le_cert = le_p12[1]
    le_exp = le_cert.not_valid_after

    return le_exp


def get_server_ids(clearpass_fqdn: str, token_type: str, access_token: str) -> list:
    """Get list of server ids"""

    url = "https://" + clearpass_fqdn + "/api/cluster/server"

    headers = {'Content-Type': 'application/json', "Authorization": "{} {}".format(token_type, access_token)}

    try:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
    except Exception as e:
        log.error(f"exception: {e}")
        exit(1)

    return {svr.get("fqdn") or svr.get("name"): svr.get("server_uuid") for svr in r.json().get('_embedded', {}).get('items', {})}


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


def put_https_cert(webserver_url: str, servers: dict, le_exp: datetime.datetime, cppm_fqdn: str, token_type: str, access_token: str) -> list:
    """Update https Certificate to CPPM"""

    # TODO need version check to use HTTPS or HTTPS(RSA) depending on version
    urls = [(svr, f"https://{cppm_fqdn}/api/server-cert/name/{uuid}/HTTPS(RSA)") for svr, uuid in servers.items()]

    payload = {
            "pkcs12_file_url": webserver_url,
            "pkcs12_passphrase": cert_passphrase
            }

    headers = {'Content-Type': 'application/json', "Authorization": f"{token_type} {access_token}"}

    _res = []
    for url in urls:
        try:
            r = requests.get(url[1], headers=headers)
            if r.ok:
                rdict = r.json()
                this_exp = rdict.get("expiry_date")
                this_exp = datetime.datetime.strptime(this_exp, '%b %d, %Y %H:%M:%S %Z')
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
                    _msg = f"LE cert has same expiration as {url[0]} https cert No Update performed"
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


def get_webserver_url() -> Tuple[str, bool]:
    my_ip = get_system_ip()
    webserver_config = cppm_config.get("webserver", {})
    webserver_base = webserver_config.get("base_url")
    webserver_port = webserver_config.get("port", 8080)
    webserver_path = webserver_config.get("path", "")
    this_is_server = True
    full_url = None
    if webserver_base:
        _ip_from_config = socket.getaddrinfo(webserver_base.replace("https://", "").replace("http://", "").split("/")[0], webserver_port)[0][-1][0]
        if _ip_from_config != my_ip:
            this_is_server = False
        full_url = f"{webserver_base}:{webserver_port}/{webserver_path}/{cert_p12}"

    if this_is_server and not full_url:
        port_str = ""
        proto = "http"
        path_str = "" if not webserver_path else f"/{webserver_path}"
        if webserver_port:
            port_str = f":{webserver_port}"
            if "443" in str(webserver_port):
                proto = "https"

        full_url = f"{proto}://{my_ip}{port_str}{path_str}/{cert_p12}"

    if not full_url:
        log.fatal("get_webserver_url() logic error, not full_url", show=True)
        sys.exit(1)

    return full_url, this_is_server


if __name__ == "__main__":
    httpd = None
    c = Console()
    # config and file verification
    verify_config()

    # get server uuids from publisher
    cluster_servers = get_server_ids(*cppm_args)

    # determine if this system is the webserver.
    # TODO refactor always start the webserver and make webserver_disable: true a config option for test
    webserver_full_url, this_is_server = get_webserver_url()

    # Start webserver to provide certs to CPPM
    if this_is_server:
        httpd = start_webserver()
    else:
        c.print(f"[dark_orange]:warning:[/] webserver [cyan]{webserver_full_url}[/] defined in config does not appear to be this system.")
        c.print("skipping web_server startup.")

    le_exp = verify_cert(this_is_server, webserver_full_url=webserver_full_url)


    # push certs
    res = put_https_cert(webserver_full_url, cluster_servers, le_exp, *cppm_args)

    if httpd:
        log.info("Stopping WebServer")
        httpd.shutdown()

    try:
        push = load_pb()
        if push and [r[1] for r in res if r[1] != "same"]:
            res_str = "\n".join([f"{svr}: {result}" for svr, result in res])
            push_res = push("ClearPass https Cert Update", res_str)
            log.debug(f"Push Response:\n{push_res}")
    except Exception as e:
        log.exception(f"PushBullet Exception: {e}")
