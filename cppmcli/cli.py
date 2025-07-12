#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from pathlib import Path

import typer

try:
    from cppmcli import cli, config, log, clishow, clisync
except (ImportError, ModuleNotFoundError):
    pkg_dir = Path(__file__).absolute().parent
    if pkg_dir.name == "cppmcli" and str(pkg_dir.parent) not in sys.argv:
        sys.path.insert(0, str(pkg_dir.parent))
    from cppmcli import cli, config, log, clishow, clisync


CONTEXT_SETTINGS = {
    # "token_normalize_func": lambda x: cli.normalize_tokens(x),
    "help_option_names": ["?", "--help"]
}

app = typer.Typer(context_settings=CONTEXT_SETTINGS, rich_markup_mode="rich")
app.add_typer(clishow.app, name="show",)
app.add_typer(clisync.app, name="sync", hidden=True)  # TODO need to move and refactor cppm-certsync to integrate into cli


def all_commands_callback(ctx: typer.Context, update_cache: bool):
    if ctx.resilient_parsing:
        config.is_completion = True
    if not ctx.resilient_parsing:
        version, debug, debugv, = None, None, None
        for idx, arg in enumerate(sys.argv[1:]):
            if idx == 0 and arg in ["-v", "-V", "--version"]:
                version = True
            if arg == "--debug":
                debug = True
            if arg == "--debugv":
                debugv = True

        debug = debug or os.environ.get("ARUBACLI_DEBUG", False)

        if version:
            cli.version_callback(ctx)
            raise typer.Exit(0)
        if debug:
            cli.debug_callback(ctx, debug=debug)
        if debugv:
            log.DEBUG = config.debug = log.verbose = config.debugv = debugv
            _ = sys.argv.pop(sys.argv.index("--debugv"))


@app.callback()
def callback(
    # ctx: typer.Context,``
    version: bool = typer.Option(False, "--version", "-V", "-v", case_sensitive=False, is_flag=True, help="Show current cencli version, and latest available version."),
    debug: bool = typer.Option(False, "--debug", is_flag=True, envvar="ARUBACLI_DEBUG", help="Enable Additional Debug Logging",),
    debugv: bool = typer.Option(False, "--debugv", is_flag=True, help="Enable Verbose Debug Logging", hidden=True, lazy=True, callback=all_commands_callback),
) -> None:
    """
    Aruba ClearPass API CLI
    """
    pass


log.debug(f'{__name__} called with Arguments: {" ".join(sys.argv)}')

if __name__ == "__main__":
    app()

click_object = typer.main.get_command(app)  # exposed for documentation
