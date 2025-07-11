#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import typer
import sys
from pathlib import Path
from rich import print


# Detect if called from pypi installed package or via cloned github repo (development)
try:
    from cppmcli import cli, cleaner
except (ImportError, ModuleNotFoundError) as e:
    pkg_dir = Path(__file__).absolute().parent
    if pkg_dir.name == "centralcli":
        sys.path.insert(0, str(pkg_dir.parent))
        from cppmcli import cli, cleaner
    else:
        print(pkg_dir.parts)
        raise e

from .response import Response
from cppmcli.api_identities import ApiIdentities, Devices

app = typer.Typer()

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
    resp: Devices = cppm.get_devices(limit=1000)
    if isinstance(resp, str):
        cli.exit(f"Call to ClearPass to fetch devices failed.  Response: {resp}")

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
    # tablefmt = cli.get_format(do_json=do_json, do_yaml=do_yaml, do_csv=do_csv, do_table=do_table, default="rich")
    # cli.display_results(resp, tablefmt=tablefmt, pager=pager, outfile=outfile, sort_by=sort_by, reverse=reverse)


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
