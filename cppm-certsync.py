#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
#
# Version: 2020-1.1
#

import datetime
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePath

import requests
from cryptography.hazmat.primitives.serialization import pkcs12
# from OpenSSL import crypto  # type: ignore

from common import cppmauth, log
cppm_config = cppmauth.config.get("CPPM", {})

cppm_args = (cppmauth.clearpass_fqdn, cppmauth.token_type, cppmauth.access_token)
cert_p12 = cppm_config.get("https_cert_p12")
cert_passphrase = cppm_config.get("https_cert_passphrase")
cert_dir = cppm_config.get("cert_dir")
webserver = cppm_config.get("webserver")
webserver_port = cppm_config.get("webserver_port", 8080)
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
    if None in [cert_p12, cert_passphrase, cert_dir, webserver, webserver_port]:
        log.fatal("config is missing a required variable, please see the example config")
        exit(1)
    elif NOTIFY and pb_key and not NOTIFY.get("service"):
        log.info("No 'service' specified for notifications, assuming PushBullet")


def verify_cert():
    p = Path(PurePath(cert_dir, cert_p12))
    if not p.exists():
        log.fatal(f"{p.name} Not Found")
        exit(1)

    # le_p12 = crypto.load_pkcs12(open(p, 'rb').read(), cert_passphrase.encode("UTF-8"))
    le_p12 = pkcs12.load_key_and_certificates(p.read_bytes(), cert_passphrase.encode("UTF-8"))
    # le_cert = le_p12.get_certificate()
    le_cert = le_p12[1]
    le_exp = le_cert.not_valid_after
    # le_exp = le_cert.get_notAfter().decode("UTF-8")
    # le_exp = datetime.datetime.strptime(le_exp, '%Y%m%d%H%M%SZ')

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


def start_webserver():
    httpd = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if s.connect_ex(("127.0.0.1", webserver_port)) == 0:
        log.warning(f"Something Appears to be Using port {webserver_port}")
    else:
        log.info(f"Starting WebServer on Port {webserver_port}")
        handler = CpHandler
        handler.CERTNAME = cert_p12
        handler.passphrase = cert_passphrase
        httpd = HTTPServer(("", webserver_port), CpHandler)
        httpd.allow_reuse_address = True
        threading.Thread(target=httpd.serve_forever, args=[2], name="webserver").start()

    return httpd


def put_https_cert(servers: dict, le_exp: datetime.datetime, cppm_fqdn: str, token_type: str, access_token: str) -> list:
    """Update https Certificate to CPPM"""

    urls = [(svr, f"https://{cppm_fqdn}/api/server-cert/name/{uuid}/HTTPS") for svr, uuid in servers.items()]

    payload = {
            "pkcs12_file_url": f"{webserver}:{webserver_port}/{cert_p12}",
            "pkcs12_passphrase": cert_passphrase
            }

    headers = {'Content-Type': 'application/json', "Authorization": f"{token_type} {access_token}"}

    _res = []
    for url in urls:
        try:
            r = requests.get(url[1], headers=headers)
            if r.ok:
                this_exp = r.json().get("expiry_date")
                this_exp = datetime.datetime.strptime(this_exp, '%b %d, %Y %H:%M:%S %Z')
                diff = le_exp - this_exp
                if diff.days > 0:
                    r = requests.put(url[1], json=payload, headers=headers)
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


if __name__ == "__main__":
    httpd = None
    # config and file verification
    verify_config()
    le_exp = verify_cert()

    # get server uuids from publisher
    cluster_servers = get_server_ids(*cppm_args)

    httpd = start_webserver()

    # push certs
    res = put_https_cert(cluster_servers, le_exp, *cppm_args)
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
