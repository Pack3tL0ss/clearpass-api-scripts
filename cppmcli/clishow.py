#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import typer
import time
import asyncio
import sys
import json
from typing import List, Iterable, Literal
from pathlib import Path
from rich import print
from rich.console import Console



# Detect if called from pypi installed package or via cloned github repo (development)
try:
    from cppmcli import cli, log, cleaner
except (ImportError, ModuleNotFoundError) as e:
    pkg_dir = Path(__file__).absolute().parent
    if pkg_dir.name == "centralcli":
        sys.path.insert(0, str(pkg_dir.parent))
        from cppmcli import cli, log, cleaner
    else:
        print(pkg_dir.parts)
        raise e

from .response import Response
from cppmcli.api_identities import ApiIdentities

app = typer.Typer()


def _build_caption(resp: Response, *, inventory: bool = False) -> str:
    dev_types = set([t.get("type", "NOTYPE") for t in resp.output])
    devs_by_type = {_type: [t for t in resp.output if t.get("type", "ERR") == _type] for _type in dev_types}
    status_by_type = {_type: {"total": len(devs_by_type[_type]), "up": len([t for t in devs_by_type[_type] if t.get("status", "") == "Up"]), "down": len([t for t in devs_by_type[_type] if t.get("status", "") == "Down"])} for _type in devs_by_type}
    _cnt_str = ", ".join([f'[{"bright_green" if not status_by_type[t]["down"] else "red"}]{t}[/]: [cyan]{status_by_type[t]["total"]}[/] ([bright_green]{status_by_type[t]["up"]}[/]:[red]{status_by_type[t]["down"]}[/])' for t in status_by_type])

    try:
        clients = sum([t.get("client_count", 0) for t in resp.output if t.get("client_count") != "-"])
        _cnt_str = f"{_cnt_str}, [bright_green]clients[/]: [cyan]{clients}[/]"
    except Exception as e:
        log.exception(f"Exception occured in _build_caption\n{e}")

    caption = "  [cyan]Show all[/cyan] displays fields common to all device types. "
    caption = f"[reset]Counts: {_cnt_str}\n{caption}To see all columns for a given device use [cyan]show <DEVICE TYPE>[/cyan]"
    # if "gw" in dev_types:
    #     caption = f"{caption}\n  [magenta]Note[/]: GW firmware version has been simplified, the actual gw version is [cyan]aa.bb.cc.dd-aa.bb.cc.dd[-beta]_build[/]"
    #     caption = f"{caption}\n  [italic]given the version is repeated it has been simplified.  You need to use the full version string when upgrading."
    if inventory:
        caption = f"{caption}\n  [italic green3]verbose listing, devices lacking name/ip are in the inventory, but have not connected to central.[/]"
    return caption

@app.command("api-clients")
def api_clients(
    client_id: str = typer.Argument(None),
):

    cppm = ApiIdentities(cli.login)
    resp = cppm.request(cppm.get_api_client) if not client_id else cppm.request(cppm.get_api_client_by_client_id, client_id)
    print(resp)

@app.command()
def devices(
    sort_by: str = typer.Option(None, "--sort", help="Field to sort by"),
    reverse: bool = typer.Option(False, "-r", is_flag=True, help="Sort in descending order"),
    do_json: bool = typer.Option(False, "--json", is_flag=True, help="Output in JSON", hidden=True),
    do_yaml: bool = typer.Option(False, "--yaml", is_flag=True, help="Output in YAML", hidden=False),
    do_csv: bool = typer.Option(False, "--csv", is_flag=True, help="Output in CSV"),
    do_table: bool = typer.Option(False, "--table", help="Output in table format",),
    cloud_auth: bool = typer.Option(False, "-C", "--cloud-auth", is_flag=True, help="Format for import into Cloud Auth. [gray42 italic]Implies CSV[/]"),
    outfile: Path = typer.Option(None, "--out", help="Output to file (and terminal)", writable=True, show_default=False,),
    pager: bool = typer.Option(False, "--pager", help="Enable Paged Output"),
    debug: bool = typer.Option(False, "--debug", envvar="ARUBACLI_DEBUG", rich_help_panel="Common Options", help="Enable Additional Debug Logging",),
):
    """Show details for All devices defined in guest device database
    """
    cppm = ApiIdentities(cli.login)
    resp = cppm.get_device(limit=1000)
    if cloud_auth:
        if any([do_json, do_yaml, do_table]):
            print(":warning:  Format option ignored as [cyan]--cloud-auth[/] option implies [cyan]--csv[/]")
        do_csv=True

    next = resp.get("_links", {}).get("next")
    out = resp.get("_embedded", {}).get("items")
    caption = ""
    if next:
        caption = ":warning: more records available.  Need to implement pagination"
    if out:
        caption = f"{caption} Device Count: [cyan]{len(out)}[/]".lstrip()

    title = "ClearPass Guest Devices"
    data = out or resp
    tablefmt = cli.get_format(do_json=do_json, do_yaml=do_yaml, do_csv=do_csv, do_table=do_table, default="rich")
    cli.display_results(data=data, title=title, caption=caption, tablefmt=tablefmt, pager=pager, outfile=outfile, sort_by=sort_by, reverse=reverse, cleaner=cleaner.get_device, cloud_auth=cloud_auth,)


@app.command()
def guests(
    sort_by: str = typer.Option(None, "--sort", help="Field to sort by"),
    reverse: bool = typer.Option(False, "-r", is_flag=True, help="Sort in descending order"),
    do_json: bool = typer.Option(False, "--json", is_flag=True, help="Output in JSON", hidden=True),
    do_yaml: bool = typer.Option(False, "--yaml", is_flag=True, help="Output in YAML", hidden=False),
    do_csv: bool = typer.Option(False, "--csv", is_flag=True, help="Output in CSV"),
    do_table: bool = typer.Option(False, "--table", help="Output in table format",),
    outfile: Path = typer.Option(None, "--out", help="Output to file (and terminal)", writable=True, show_default=False,),
    pager: bool = typer.Option(False, "--pager", help="Enable Paged Output"),
    debug: bool = typer.Option(
        False, "--debug", envvar="ARUBACLI_DEBUG", help="Enable Additional Debug Logging",
    ),
) -> None:
    """Show details registered Guest users.
    """
    raise NotImplementedError()
    tablefmt = cli.get_format(do_json=do_json, do_yaml=do_yaml, do_csv=do_csv, do_table=do_table, default="rich")
    cli.display_results(resp, tablefmt=tablefmt, pager=pager, outfile=outfile, sort_by=sort_by, reverse=reverse)


@app.command()
def version(
    debug: bool = typer.Option(
        False, "--debug", envvar="ARUBACLI_DEBUG", help="Enable Additional Debug Logging",
    ),
) -> None:
    """Show current cencli version, and latest available version.
    """
    cli.version_callback()


def _get_cencli_config(
    debug: bool = typer.Option(
        False,
        "--debug",
        envvar="ARUBACLI_DEBUG",
        help="Enable Additional Debug Logging",
    ),
) -> None:

    try:
        from cppmcli import config
    except (ImportError, ModuleNotFoundError):
        pkg_dir = Path(__file__).absolute().parent
        if pkg_dir.name == "cppm":
            sys.path.insert(0, str(pkg_dir.parent))
            from cppmcli import config

    omit = []
    out = {k: str(v) if isinstance(v, Path) else v for k, v in config.__dict__.items() if k not in omit}

    resp = Response(output=out)

    cli.display_results(resp, stash=False, tablefmt="yaml")


@app.callback()
def callback():
    """
    Show Collect information from ClearPass
    """
    pass


if __name__ == "__main__":
    app()
