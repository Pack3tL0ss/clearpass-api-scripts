#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
#
# Version: 2025-10.0
#
from __future__ import annotations

import datetime
import socket
import sys
import threading
import zoneinfo
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Tuple

import pendulum
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from rich.console import Console
from rich.markdown import Markdown
from yarl import URL

from common import log, utils
from common.cppmauth import ClearPassAuth

if TYPE_CHECKING:
    from common.config import Certificate

from rich.traceback import install

install(show_locals=True)

UpdateRes = Literal["updated", "same", "older", "error"]
Service = Literal["HTTPS", "HTTPS(RSA)", "RADIUS", "RadSec"]


console = Console()
econsole = Console(stderr=True)
cppm = ClearPassAuth()

# NOTE: logger defaults to show=True meaning it will write formatted output to stderr, and clean output (formatting stripped) to the log file
# use show=False to only log to file.


# certificate expiry looks like 'Apr 04, 2025 14:04:11 CDT'
# CDT is not valid IANA tz Identifier.  So we iterate through all valid TimeZones
# and generate tzname names until we find a match, then return that ZoneInfo object
def _get_timezone_from_abbr(abbr) ->zoneinfo.ZoneInfo | str:
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
    def do_GET(self):
        p = cppm.webserver.web_root / self.path.split("/")[-1]
        if p.exists():
            log.info(f"Sending {p.name} to {self.address_string()}")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pkcs12")
            self.end_headers()
            self.wfile.write(p.read_bytes())
        else:
            log.error(f"Unable to process request from [cyan]{self.address_string()}[/] for [cyan]{p.name}[/].  [cyan]{p}[/] [red]File Not Found[/].")
            self.send_error(404)
        return


@lru_cache(typed=True)
def get_le_cert_from_external(webserver_full_url: str):
    try:
        r = requests.get(webserver_full_url)
        if not r.ok:
            log.error(f"Failed to get cert from external webserver {webserver_full_url} [dim]{r.status_code}[/] [red]{r.reason}[/]")
            utils.exit()
        else:
            return r.content
    except Exception as e:
        log.exception(f"Exception occured while getting current LE cert from {webserver_full_url}. {e.__class__.__name__}")
        log.exception(e, show=False)
        utils.exit()


def get_cert_expiration(cert_p12: str, cert_passphrase: str, webserver_url: URL | str) -> datetime.datetime:
    webserver_url: URL = webserver_url if isinstance(webserver_url, URL) else URL(webserver_url)
    full_url = webserver_url / cert_p12
    p, pb = None, None
    if not cppm.webserver.local:
        pb = get_le_cert_from_external(full_url)
        log.debug(get_le_cert_from_external.cache_info())
    else:
        local_paths: List[Path] = [(cppm.webserver.web_root or Path().home()) / cert_p12, Path().cwd() / cert_p12]
        for p in local_paths:
            if p.exists():
                pb = p.read_bytes()
                break
        if not pb:
            log.fatal(f"{cppm.webserver.web_root / cert_p12} Not Found")
            utils.exit()

    try:
        le_p12 = pkcs12.load_key_and_certificates(pb, cert_passphrase.encode("UTF-8"), backend=default_backend())
        le_cert = le_p12[1]
        le_exp = le_cert.not_valid_after_utc
    except Exception as e:
        _msg = f"[dark_orange3]:warning:[/]  [red]Exception[/]: [dim italic]({e.__class__.__name__}, {e})[/] in [cyan]get_cert_expiration[/]: During Attempt to get expiration from PKCS12 data.  Host: [magenta]{full_url.host}[/] Certificate: [cyan]{cert_p12}[/]."
        if pb and "</html>" in str(pb):
            _msg += f"  Response appears to be html not a PKCS12 certificate.  Perhaps the path ({full_url.path}) or port ({full_url.port}) is wrong."
        _msg += "  [red italic]Script will exit[/]."
        log.error(_msg)
        log.exception(e, show=False)
        utils.exit()

    return le_exp


def _get_server_ids() -> Dict[str, str]:
    """Get list of server ids"""

    url = f"https://{cppm.fqdn}/api/cluster/server"

    headers = {"Content-Type": "application/json", "Authorization": f"{cppm.token_type} {cppm.access_token}"}

    try:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
    except Exception as e:
        log.error(f"Exception: {e.__class__.__name__} {e}")
        utils.exit(code=1)

    servers: List[Dict[str, str]] = r.json().get("_embedded", {}).get("items", {})
    return {svr.get("name"): svr.get("server_uuid") for svr in sorted(servers, key=lambda s: s["name"])}


def start_webserver(port: int = None, serve_only: bool = False) -> HTTPServer | None:
    port = port or cppm.webserver.port
    def _start_webserver(port: int = None):
        httpd = None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            log.warning(f"Something Appears to be Using port {port}")
        else:
            log.info(f"Starting WebServer on Port {port}")
            httpd = HTTPServer(("", port), CpHandler)
            httpd.allow_reuse_address = True
            threading.Thread(target=httpd.serve_forever, args=[2], name="webserver").start()

        return httpd

    if not cppm.webserver.local:
        if not cppm.webserver.valid:
            econsole.print("[dark_orange3]:warning:[/]  [red italic]Skipping web_server startup[/], [cyan]webserver[/] section missin or invalid.  [dim italic][cyan]base_url[/] is [red]required[/][/dim italic]")
        else:
            econsole.print("[yeallow]:information:[/]  [dark_olive_green3 italic]Skipping web_server startup, based on config.[/]")
        return

    httpd = _start_webserver(port=port)
    if serve_only:
        try:
            econsole.print("[yeallow]:information:[/]  webserver only mode.  Use [cyan]CTRL-C[/] to stop webserver")
            while True:
                import time
                time.sleep(3)
        except (KeyboardInterrupt, EOFError):
            log.info("Stopping WebServer", show=False)
            httpd.shutdown()
            utils.exit("[red]:stop_sign:[/]  WebServer Stopped", code=0)

    return httpd


def _get_update_certs() -> Dict[str, Certificate]:
    server_version = _get_server_version()
    svc_map = {
        "https_rsa": "HTTPS" if server_version.minor < 10 else "HTTPS(RSA)",
        "https_ecc": "HTTPS(ECC)",
        "radius": "RADIUS",
        "radsec": "RadSec"
    }

    flags = [f"--{k.replace('_', '-')}" for k in svc_map.keys()]
    push_list = [svc for flag, svc in zip(flags, svc_map.keys()) if flag in sys.argv] or list(svc_map.keys())

    return {svc_map.get(k, k): v for k, v in cppm.certificates.items() if k in push_list}


def get_expiry_from_response(rdict: Dict[str, str]) -> pendulum.DateTime:
    this_exp = rdict["expiry_date"]  # looks like 'Apr 04, 2025 14:04:11 CDT'
    tzstr = " ".join(this_exp.split()[-1:])  # zz format specifier doesn't work so need to split tz out.  See https://github.com/python-pendulum/pendulum/issues/279
    tzstr = _get_timezone_from_abbr(tzstr)
    this_exp = pendulum.from_format(" ".join(this_exp.split()[0:-1]), "MMM DD, YYYY HH:mm:ss", tz=tzstr)

    return this_exp.in_timezone("UTC")

class ClearPassURL:
    def __init__(self, name: str, url: str | URL, *, cert_p12: str, cert_passphrase: str):
        self.name: str = name
        self.url: URL = url if isinstance(url, URL) else URL(url)
        self.cert_p12 = cert_p12.lstrip("/")
        self.cert_passphrase = cert_passphrase
        self.svc = self.url.name

    @property
    def payload(self)-> Dict[str, str]:
        return {
            "pkcs12_file_url": f"{cppm.webserver.url}/{self.cert_p12}",
            "pkcs12_passphrase": self.cert_passphrase,
        }



    def __iter__(self):
        return iter((self.cert_p12, self.cert_passphrase))

def put_certs() -> List[Tuple[str, Service, UpdateRes]]:
    """Update Certificates on CPPM nodes"""

    servers = _get_server_ids()
    certs = _get_update_certs()

    req_data: List[ClearPassURL] = []
    for svc in certs:
        cert_p12 = certs[svc].p12
        cert_passphrase = certs[svc].passphrase
        req_data += [ClearPassURL(svr, url=f"https://{cppm.fqdn}/api/server-cert/name/{uuid}/{svc}", cert_p12=cert_p12, cert_passphrase=cert_passphrase) for svr, uuid in servers.items()]

    _res = []
    for req in req_data:
        try:
            r = requests.get(req.url, headers=cppm.headers)
            if not r.ok:
                _res.append((req.name, req.svc, "error"))
                log.error(f"[GET: [italic]{r.url}[/]] {r.status_code} {r.reason}")
            else:
                rdict: Dict[str, str | int | List[str], Dict[str, Any] | bool] = r.json()
                this_exp = get_expiry_from_response(rdict)
                le_exp = get_cert_expiration(*req, webserver_url=cppm.webserver.url)
                diff = le_exp - this_exp
                is_self_signed = True if rdict.get("subject", "subject") == rdict.get("issued_by", "") else False
                if diff.days > 0 or is_self_signed:
                    if is_self_signed:
                        log.info(f"[bright_green]Updating[/] [dark_olive_green3]{req.name}[/] [cyan]{req.svc}[/] certificate as the current cert is self signed.")

                    # tell cppm to download new cert
                    r = requests.put(req.url, json=req.payload, headers=cppm.headers, verify=False)
                    _res.append((req.name, req.svc, "updated") if r.status_code == 200 else (req.name, req.svc, "error"))
                    _log_func = log.info if r.ok else log.error
                    _log_func(f"[PUT: [italic]{r.url}[/]] {r.status_code} {r.reason}")
                else:
                    words = ('same', 'as') if diff.days == 0 else ('older', 'than')
                    _msg = f"New cert has {words[0]} expiration {words[1]} {req.name} {req.svc} cert. No Update performed."
                    _res.append((req.name, req.svc, words[0]))
                    log.info(_msg)
        except Exception as e:
            _msg = f"[red]Exception[/]: [dim italic]({e.__class__.__name__}, {e})[/] in [cyan]put_certs[/]: During Attempt to update [magenta]{req.name}[/] [cyan]{req.svc}[/] certificate @ URL [cyan]{req.url}[/] with new certificate @ {cppm.webserver.url / req.cert_p12}"
            log.error(_msg, show=True)
            log.exception(e, show=False)

    return _res

class Version:
    def __init__(self, version: str):
        self.major, self.minor, self.patch, self.build = map(int, version.split("."))

    def __str__(self):
        return ".".join([self.major, self.minor, self.patch, self.build])


def _get_server_version() -> Version:
    """Get server version"""

    url = f"https://{cppm.fqdn}/api/server/version"

    try:
        r = requests.get(url, headers=cppm.headers)
        r.raise_for_status()
    except Exception as e:
        log.error(f"[red]:warning:[/]  exception: {e}")
        exit(1)

    try:
        return Version(r.json().get("cppm_version"))
    except Exception as e:
        print(f"[dark_orange3]:warning:[/]  {e.__class__.__class__}, {e}")
        log.error(e)
        exit(1)


def _load_pb():
    if cppm.notify and cppm.notify.key:
        try:
            from common.notify import Push
        except ImportError:
            log.error("An API key for PushBullet was provided but the PushBullet Module was not found")
            log.error("\t Likely Need to 'venv/bin/python3 -m pip install pushbullet.py'")
            return

        return Push(cppm.notify.key).sendpush


def do_push(res):
    push = _load_pb()
    try:
        if push and [r[2] for r in res if r[2] not in ["same", "older"]]:
            res_str = "\n".join([f"{svr} ({svc}): {result}" for svr, svc, result in res])
            push_res = push("ClearPass Cert Update", res_str)
            log.debug(f"Push Response:\n{push_res}")
    except Exception as e:
        log.exception(f"PushBullet Exception: {e}")


def help_from_md():
    md = []
    readme_file = Path(__file__).parent / "README.md"
    readme_txt = readme_file.read_text()
    capture = False
    for line in readme_txt.splitlines():
        if '#### Command Line Arguments' in line:
            capture = True
        elif capture and line.startswith("#"):
            capture = False
            break
        if capture:
            md += [line]

    md = Markdown("\n".join(md))

    print()
    console.rule('The Following is extracted from the readme')
    console.print(md)
    console.rule()
    console.print("[yellow]:information:[/] [dark_olive_green3 italic]Refer to README @ https://github.com/Pack3tL0ss/clearpass-api-scripts/tree/main for more details[/]")

class Args:
    def __init__(self, port: int | None, serve_only: bool, push: bool):
        self.port = port
        self.serve_only = serve_only
        self.push = push

def process_args() -> Args:
    """Currently only processing the port
    """
    if "--help" in sys.argv or "?" in sys.argv:
        utils.exit(help_from_md(), code=0)

    port = None
    if "--port" in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index("--port") + 1])
        except IndexError:
            utils.exit("Missing argument after [cyan]--port[/] :triangular_flag:")
        except ValueError:
            utils.exit(f"Invalid argument after? [cyan]--port[/] :triangular_flag: {sys.argv[sys.argv.index("--port") + 1]} should be a valid integer.")
    serve_only = True if "--serve-only" in sys.argv else False
    push = False if "--no-push" in sys.argv else True
    if "--debug" in sys.argv:
        cppm.DEBUG = log.DEBUG = True
    # --https-rsa, --https-ecc, --radsec, and --radius flags are processed in _get_update_certs

    return Args(port=port, serve_only=serve_only, push=push)


if __name__ == "__main__":
    # TODO make part of cpcli can handle flags there
    if not cppm.valid_cert_sync:
        utils.exit(f"Configuration file {cppm.file} does not appear to be valid.  Refer to example @ https://raw.githubusercontent.com/Pack3tL0ss/clearpass-api-scripts/refs/heads/main/config.yaml.example")
    args = process_args()
    httpd = start_webserver(port=args.port, serve_only=args.serve_only)  # determines if it should actually start in the function
    res = put_certs()
    if httpd:
        log.info("[red]:stop_sign:[/]  Stopping WebServer")
        httpd.shutdown()

    if args.push:
        do_push(res)
