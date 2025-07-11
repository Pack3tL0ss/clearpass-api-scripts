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

sys.path.insert(0, Path(__file__).absolute().parent.parent)
# import cppm_certsync as certsync

app = typer.Typer()

@app.command()
def certs(
    port: int = typer.Option(None, help="Override the port used to reach the webserver containing the certificates"),
):
    """Sync certificates from local directory (webserver will start locally) or external webserver containing LetsEncrypt or the like certificates.
    """
    ...


@app.callback()
def callback():
    """
    Sync Certificates
    """
    pass


if __name__ == "__main__":
    app()
