#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Common functions used throughout the CLI app
"""

from __future__ import annotations

import sys
import typer
import json
# import pkg_resources
from .config import Config
from .logger import MyLogger
from pyclearpass import ClearPassAPILogin
from typing import Literal, List, Union
from pathlib import Path
from rich.console import Console
from rich import print
import requests


# Detect if called from pypi installed package or via cloned github repo (development)
try:
    from cppmcli import log, config, utils, render
except (ImportError, ModuleNotFoundError) as e:
    pkg_dir = Path(__file__).absolute().parent
    if pkg_dir.name == "cppmcli":
        sys.path.insert(0, str(pkg_dir.parent))
        from cppmcli import log, config, utils, render
    else:
        print(pkg_dir.parts)
        raise e

from cppmcli.objects import DateTime, Encoder
from cppmcli.response import Response


TableFormat = Literal["json", "yaml", "csv", "rich", "simple", "tabulate", "raw", "action"]
console = Console()
econsole = Console(stderr=True)
tty = utils.tty


class CLICommon:
    def __init__(self, config: Config, logger: MyLogger, raw_out: bool = False):
        self.config = config
        self.log = logger
        self.raw_out = raw_out

    @property
    def login(self):
        token = self.get_api_token(self.config.fqdn, client_id=self.config.client_id, client_secret=self.config.client_secret, username=self.config.username, password=self.config.password, verify_ssl=self.config.verify_ssl)
        token = token.get("access_token")
        return ClearPassAPILogin(
            server=self.config.fqdn,
            granttype="client_credentials",
            clientsecret=self.config.client_secret,
            clientid=self.config.client_id,
            username=self.config.username,
            password=self.config.password,
            api_token=token,
            verify_ssl=False
        )

    @staticmethod
    def exit(msg: str = None, code: int = 1, emoji: bool = True) -> None:
        """Print msg text and exit.

        Prepends warning emoji to msg if code indicates an error.
            emoji arg has not impact on this behavior.
            Nothing is displayed if msg is not provided.

        Args:
            msg (str, optional): The msg to display (supports rich markup). Defaults to None.
            code (int, optional): The exit status. Defaults to 1 (indicating error).
            emoji (bool, optional): Set to false to disable emoji. Defaults to True.

        Raises:
            typer.Exit: Exit
        """
        console = Console(emoji=emoji, stderr=bool(code))
        if code != 0:
            msg = f"[dark_orange3]\u26a0[/]  {msg}" if msg else msg  # \u26a0 = ⚠ / :warning:

        if msg:
            console.print(msg)
        raise typer.Exit(code=code)

    def get_api_token(self, server: str, *, grant_type: str = "client_credentials", client_id: str = None, client_secret: str = None, username: str = None, password: str = None, verify_ssl: bool = False):
        """
        Operation: Obtain an OAuth2 access token for making API calls
        HTTP Status Response Codes: 200 OK, 400 Bad Request, 406 Not Acceptable, 415 Unsupported Media Type, 200 OK, 400 Bad Request, 406 Not Acceptable, 415 Unsupported Media Type
        Required Body Parameters (body description)- TokenEndpoint {grant_type (string) = ['client_credentials' or 'password' or 'refresh_token']: OAuth2 authentication method,client_id (string): Client ID defined in API Clients,client_secret (string, optional): Client secret, required if the API client is not a public client,username (string, optional): Username for authentication, required for grant_type "password",password (string, optional): Password for authentication, required for grant_type "password",scope (string, optional): Scope of the access request,refresh_token (string, optional): Refresh token issued to the client, required for grant_type "refresh_token"}
        Required Body Parameters (type(dict) body example)- {
        "grant_type": "",
        "client_id": "",
        "client_secret": "",
        "username": "",
        "password": "",
        "scope": "",
        "refresh_token": ""
        }
        """
        model = {
            "grant_type": grant_type,
            "client_id": client_id or "",
            "client_secret": client_secret or "",
            "username": username or "",
            "password": password or "",
        }

        full_url_path = f"https://{server.removeprefix('https://')}/api/oauth"
        response = requests.post(url=full_url_path, json=model, verify=verify_ssl)

        try:
            response = json.loads(str(response.text))
            return response

        except json.decoder.JSONDecodeError:
            return response

    def version_callback(self, ctx: typer.Context | None = None,):
        if ctx is not None and ctx.resilient_parsing:  # tab completion, return without validating
            return

        # print(pkg_resources.get_distribution('cppm').version)
        econsole.print("Version command not implemented yet.")

    def debug_callback(self, ctx: typer.Context, debug: bool):
        if ctx.resilient_parsing:  # tab completion, return without validating
            return False

        if debug:
            self.log.DEBUG = self.config.debug = debug
            return debug

    def verbose_debug_callback(self, ctx: typer.Context, debugv: bool):
        if ctx.resilient_parsing:  # tab completion, return without validating
            return False

        if debugv:
            self.log.DEBUG = self.log.verbose = self.config.debug = self.config.debugv = debugv
            return debugv

    @staticmethod
    def get_format(
        do_json: bool = False, do_yaml: bool = False, do_csv: bool = False, do_table: bool = False, default: str = "rich"
    ) -> TableFormat:
        """Simple helper method to return the selected output format type (str)"""
        if do_json:
            return "json"
        elif do_yaml:
            return "yaml"
        elif do_csv:
            return "csv"
        elif do_table:
            return "rich" if default != "rich" else "tabulate"
        else:
            return default

    @staticmethod
    def write_file(outfile: Path, outdata: str) -> None:
        """Output data to file

        Args:
            outfile (Path): The file to write to.
            outdata (str): The text to write.
        """
        if outfile and outdata:
            if config.cwd != config.outdir:
                if (
                    outfile.parent.resolve().name == "central-api-cli" and
                    Path.joinpath(outfile.parent.resolve() / ".git").is_dir()
                ):
                    # outdir = Path.home() / 'cencli-out'
                    print(
                        "\n[bright_green]You appear to be in the development git dir.\n"
                        f"Exporting to[/] [cyan]{config.outdir.relative_to(config.cwd)}[/] directory."
                    )
                    config.outdir.mkdir(exist_ok=True)
                    outfile = config.outdir / outfile

            print(f"\n[cyan]Writing output to {outfile}... ", end="")

            out_msg = None
            try:
                if isinstance(outdata, (dict, list)):
                    outdata = json.dumps(outdata, indent=4)
                outfile.write_text(outdata)  # typer.unstyle(outdata) also works
            except Exception as e:
                outfile.write_text(f"{outdata}")
                out_msg = f"Error ({e.__class__.__name__}) occurred during attempt to output to file.  " \
                    "Used simple string conversion"

            print("[italic green]Done")
            if out_msg:
                log.warning(out_msg, show=True)


    def _display_results(
        self,
        data: Union[List[dict], List[str], dict, None] = None,
        tablefmt: str = "rich",
        title: str = None,
        caption: str = None,
        pager: bool = False,
        outfile: Path = None,
        sort_by: str = None,
        reverse: bool = False,
        stash: bool = True,
        set_width_cols: dict = None,
        full_cols: Union[List[str], str] = [],
        fold_cols: Union[List[str], str] = [],
        cleaner: callable = None,
        **cleaner_kwargs,
    ):
        # @staticmethod
        # def get_sort(sort_value: Any, type_):
        #     if isinstance(sort_value, DateTime):
        #         return sort_value.epoch
        #     elif  type_ == int or all([v == "-" for v in d[sort_by]]):
        #         return 0
        if data:
            data = utils.listify(data)

            if cleaner and not self.raw_out:
                data = cleaner(data, **cleaner_kwargs)
                data = utils.listify(data)

            if sort_by and all(isinstance(d, dict) for d in data):
                if sort_by not in data[0] and sort_by.replace("_", " ") in data[0]:
                    sort_by = sort_by.replace("_", " ")

                # TODO move this to log.caption so it's at end of output
                if not all([True if sort_by in d else False for d in data]):
                    print(f":x: [dark_orange3]Error: [cyan]{sort_by}[reset] does not appear to be a valid field")
                    print("Valid Fields:\n----------\n{}\n----------".format("\n".join(data[0].keys())))
                    # print("Valid Fields:\n----------\n{}\n----------".format("\n".join([k.replace(" ", "_") for k in data[0].keys()])))  # TODO verify if sort field name is b4 or after cleaner and how sort handles space
                else:
                    try:
                        type_ = str
                        for d in data:
                            if d[sort_by] is not None:
                                type_ = type(d[sort_by])
                                break
                        data = sorted(data, key=lambda d: d[sort_by] if d[sort_by] != "-" else 0 or 0 if type_ is int else "")

                    except TypeError as e:
                        print(
                            f":x: [dark_orange3]Warning:[reset] Unable to sort by [cyan]{sort_by}.\n   {e.__class__.__name__}: {e} "
                        )

            if reverse:
                data = data[::-1]

            if self.raw_out and tablefmt in ["simple", "rich"]:
                tablefmt = "json"

            kwargs = {
                "outdata": data,
                "tablefmt": tablefmt,
                "title": title,
                "caption": caption,
                "config": config,
                "set_width_cols": set_width_cols,
                "full_cols": full_cols,
                "fold_cols": fold_cols,
            }
            with console.status("Rendering Output..."):
                outdata = render.output(**kwargs)

            if stash:
                config.last_command_file.write_text(
                    json.dumps({k: v if not isinstance(v, DateTime) else v.epoch for k, v in kwargs.items() if k != "config"}, cls=Encoder)
                )

            typer.echo_via_pager(outdata) if pager and tty and len(outdata) > tty.rows else typer.echo(outdata)

            if outfile and outdata:
                self.write_file(outfile, outdata.file)
        else:
            log.warning(f"No data passed to _display_output {title} {caption}")

    def display_results(
        self,
        resp: Union[Response, List[Response]] = None,
        data: Union[List[dict], List[str], dict, None] = None,
        tablefmt: TableFormat = "rich",
        title: str = None,
        caption: str = None,
        pager: bool = False,
        outfile: Path = None,
        sort_by: str = None,
        reverse: bool = False,
        stash: bool = True,
        exit_on_fail: bool = False,
        set_width_cols: dict = None,
        full_cols: Union[List[str], str] = [],
        fold_cols: Union[List[str], str] = [],
        cleaner: callable = None,
        **cleaner_kwargs,
    ) -> None:
        """Output Formatted API Response to display and optionally to file

        one of resp or data attribute is required

        Args:
            resp (Union[Response, List[Response], None], optional): API Response objects.
            data (Union[List[dict], List[str], None], optional): API Response output data.
            tablefmt (str, optional): Format of output. Defaults to "rich" (tabular).
                Valid Values: "json", "yaml", "csv", "rich", "simple", "tabulate", "raw", "action"
                Where "raw" is unformatted raw response and "action" is formatted for POST|PATCH etc.
                where the result is a simple success/error.
            title: (str, optional): Title of output table.
                Only applies to "rich" tablefmt. Defaults to None.
            caption: (str, optional): Caption displayed at bottom of table.
                Only applies to "rich" tablefmt. Defaults to None.
            pager (bool, optional): Page Output / or not. Defaults to True.
            outfile (Path, optional): path/file of output file. Defaults to None.
            sort_by (Union[str, List[str], None] optional): column or columns to sort output on.
            reverse (bool, optional): reverse the output.
            stash (bool, optional): stash (cache) the output of the command.  The CLI can re-display with
                show last.  Default: True
            ok_status (Union[int, List[int], Tuple[int, str], List[Tuple[int, str]]], optional): By default
                responses with status_code 2xx are considered OK and are rendered as green by
                Output class.  provide int or list of int to override additional status_codes that
                should also be rendered as success/green.  provide a dict with {int: str, ...}
                where string can be any color supported by Output class or "neutral" "success" "fail"
                where neutral is no formatting, and success / fail will use the default green / red respectively.
            set_width_cols (Dict[str: Dict[str, int]]): Passed to output function defines cols with min/max width
                example: {'details': {'min': 10, 'max': 30}, 'device': {'min': 5, 'max': 15}}
            full_cols (list): columns to ensure are displayed at full length (no wrap no truncate)
            cleaner (callable, optional): The Cleaner function to use.
        """
        if resp is not None:
            resp = utils.listify(resp)

            # update caption with rate limit
            if resp[-1].rl:
                rl_str = f"[reset][italic dark_olive_green2]{resp[-1].rl}[/]".lstrip()
                caption = f"{caption}\n  {rl_str}" if caption else f"  {rl_str}"

            if log.caption:
                caption = f'{caption}\n[bright_red]  !!! Partial command failure !!!\n{log.caption}[/]'

            for idx, r in enumerate(resp):
                # Multi request url line (example below)
                # Request 1 [POST: /platform/device_inventory/v1/devices]
                #  Response:
                m_colors = {
                    "GET": "bright_green",
                    "DELETE": "red",
                    "PATCH": "dark_orange3",
                    "PUT": "dark_orange3",
                    "POST": "dark_orange3"
                }
                fg = "bright_green" if r else "red"
                conditions = [len(resp) > 1, tablefmt in ["action", "raw"], r.ok and not r.output]
                if any(conditions):
                    _url = r.url if not hasattr(r.url, "path") else r.url.path
                    m_color = m_colors.get(r.method, "reset")
                    print(
                        f"Request {idx + 1} [[{m_color}]{r.method}[reset]: "
                        f"[cyan]{_url}[/cyan]]\n [fg]Response[reset]:"
                    )

                if self.raw_out:
                    tablefmt = "raw"

                # Nothing returned in response payload
                if not r.output:
                    print(f"  Status Code: [{fg}]{r.status}[/]")
                    print("  :warning: Empty Response.  This may be normal.")

                if not r or tablefmt in ["action", "raw"]:

                    # raw output (unformatted response from Aruba Central API GW)
                    if tablefmt == "raw":
                        status_code = f"[{fg}]status code: {r.status}[/{fg}]"
                        print(r.url)
                        print(status_code)
                        if not r.ok:
                            print(r.error)
                        print("[bold cyan]Unformatted response from Aruba Central API GW[/bold cyan]")
                        plain_console = Console(color_system=None, emoji=False)
                        plain_console.print(r.raw)

                        if outfile:
                            self.write_file(outfile, r.raw)

                    # prints the Response objects __str__ method which includes status_code
                    # and formatted contents of any payload. example below
                    # status code: 201
                    # Success
                    else:
                        console.print(f"[{fg}]{r}[/]")

                    if idx + 1 == len(resp):
                        if caption:
                            print(caption.replace(rl_str, ""))
                        console.print(f"\n{rl_str}")

                # response to single request are sent to _display_results for full output formatting. (rich, json, yaml, csv)
                else:
                    self._display_results(
                        r.output,
                        tablefmt=tablefmt,
                        title=title,
                        caption=caption if idx == len(resp) - 1 else None,
                        pager=pager,
                        outfile=outfile,
                        sort_by=sort_by,
                        reverse=reverse,
                        stash=stash,
                        set_width_cols=set_width_cols,
                        full_cols=full_cols,
                        fold_cols=fold_cols,
                        cleaner=cleaner,
                        **cleaner_kwargs
                    )

            # TODO make elegant caas send-cmds uses this logic
            if cleaner and cleaner.__name__ == "parse_caas_response":
                print(caption)

            if exit_on_fail and not all([r.ok for r in resp]):
                raise typer.Exit(1)

        elif data:
            self._display_results(
                data,
                tablefmt=tablefmt,
                title=title,
                caption=caption,
                pager=pager,
                outfile=outfile,
                sort_by=sort_by,
                reverse=reverse,
                stash=stash,
                set_width_cols=set_width_cols,
                full_cols=full_cols,
                fold_cols=fold_cols,
                cleaner=cleaner,
                **cleaner_kwargs
            )


if __name__ == "__main__":
    pass
