#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This will replace the Output class and output func currently living in utils.py

cleaner.py still normalizes the responses from the API
render.py (this file) takes the normalized data, and displays it (various formats)
'''
from __future__ import annotations
import sys
from pathlib import Path
from typing import Any, Dict, List, Literal, Union

import tabulate
import typer
import yaml
import json
from pygments import formatters, highlight
from rich.box import HORIZONTALS, SIMPLE
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Detect if called from pypi installed package or via cloned github repo (development)
try:
    from cppmcli import log, utils
except (ImportError, ModuleNotFoundError):
    pkg_dir = Path(__file__).absolute().parent
    if pkg_dir.name == "cppmcli" and str(pkg_dir.parent) not in sys.path:
        sys.path.insert(0, str(pkg_dir.parent))
    from cppmcli import log, utils
    # else:
    #     print(pkg_dir.parts)
    #     raise e

from cppmcli.config import Config
from cppmcli.objects import Encoder

tty = utils.tty
CASE_SENSITIVE_TOKENS = ["R", "U"]
TableFormat = Literal["json", "yaml", "csv", "rich", "simple", "tabulate", "raw", "action"]
REDACT = ["mac", "serial", "neighborMac", "neighborSerial", "neighborPortMac", "longitude", "latitude"]
RICH_FULL_COLS = ['mac', 'serial', 'ip', 'public ip', 'version', 'radio', 'id']
RICH_FOLD_COLS = ["description"]
console = Console(emoji=False)


CUST_KEYS = ["customer_id", "customer_name", "cid", "cust_id"]

class Output:
    def __init__(self, rawdata: str = "", prettydata: str = "", config=None):
        self.config = config
        self._file = rawdata  # found typer.unstyle AFTER I built this
        self.tty = prettydata

    def __len__(self):
        return len(str(self).splitlines())

    def __str__(self):
        pretty_up = typer.style("Up\n", fg="green")
        pretty_down = typer.style("Down\n", fg="red")
        if self.tty:
            out = self.tty.replace("Up\n", pretty_up).replace("Down\n", pretty_down)
        else:
            out = self.file

        out = self.sanitize_strings(out)
        return out

    def __iter__(self):
        out = self.tty or self.file
        out = out.splitlines(keepends=True)
        out = self.sanitize_strings(out)
        for line in out:
            yield line

    def __contains__(self, item):
        return item in self.file

    def sanitize_strings(self, strings: str, config=None) -> str:
        """Sanitize Output for demos

        Args:
            strings (str): Unsanitized command output.
            config (Config, optional): Pass in cencli.Config object.

        Returns:
            str: Sanitized str output with sensitive data redacted.
        """
        config = config or self.config
        if config and config.sanitize and config.sanatize_file.is_file():
            sanitize_data = config.get_file_data(config.sanatize_file)
            for s in sanitize_data.get("redact_strings", {}):
                strings = strings.replace(s, f"{'--redacted--':{len(s)}}")
            for s in sanitize_data.get("replace_strings", []):
                if s:
                    for old, new in s.items():
                        strings = strings.replace(old, f"{new:{len(old)}}")
        return strings

    def menu(self, data_len: int = None) -> str:
        def isborder(line: str) -> bool:
            return all(not c.isalnum() for c in list(line))

        out = self.tty or self.file
        out = out.splitlines(keepends=True)
        out = self.sanitize_strings(out)
        _out = []
        data_start = 3
        if data_len:
            data_start = len(self) - data_len - 1
        else:
            for idx, line in enumerate(out):
                if "name" in line:
                    if not isborder(out[idx + 2]):
                        data_start = idx + 2
        for idx, line in enumerate(out):
            i = idx - data_start + 1
            pad = len(str(len(out[data_start:])))  # non indexed lines
            ipad = pad - len(str(i))               # indexed lines
            _out += [
                f"  {' ':{pad}}{line}" if isborder(line) or idx < data_start else f"{i}.{' ' * ipad}{line}"
            ]
        return "".join(_out)

    @property
    def file(self):
        return "" if not self._file else typer.unstyle(self._file)


def do_pretty(key: str, value: str) -> str:
    """Apply coloring to tty output

    Applies color to certain columns/values prior to formatting
    """
    color = "green" if value.lower() == "up" else "red"
    value = "" if value is None else value  # testing error on cop
    return value if key != "status" else f'[b {color}]{value.title()}[/b {color}]'

def _do_subtables(data: List[dict], tablefmt: str = "rich") -> List[dict]:
    """Parse data and format any values that are dict, list, tuple

    Args:
        data (list): The data
        tablefmt (str, optional): table format. Defaults to "rich".

    Returns:
        List[dict]: Original dict with any inner (dict/list/tuples)
                    formatted to match tablefmt specified.
    """
    out = []
    for inner_dict in data:  # the object: switch/vlan etc dict
        for key, val in inner_dict.items():
            if not isinstance(val, (list, dict, tuple)):
                if val is None:
                    inner_dict[key] = ''
                elif isinstance(val, str) and val.lower() in ['up', 'down']:
                    color = 'red' if val.lower() == 'down' else 'green'
                    if tablefmt == 'rich':
                        inner_dict[key] = f'[b {color}]{val.title()}[/b {color}]'
                    else:
                        inner_dict[key] = typer.style(val.title(), fg=color)
                else:
                    if tablefmt == 'rich':
                        inner_dict[key] = Text(str(val), style=None)
                    else:
                        inner_dict[key] = str(val)
            else:
                val = utils.listify(val)
                if val and tablefmt == "rich" and hasattr(val[0], 'keys'):
                    inner_table = Table(*(k for k in val[0].keys()),
                                        show_header=True,
                                        pad_edge=False,
                                        collapse_padding=True,
                                        show_edge=False,
                                        header_style="bold cyan",
                                        box=SIMPLE
                                        )
                    _ = [inner_table.add_row(*[do_pretty(kk, str(vv)) for kk, vv in v.items()]) for v in val]
                    console.begin_capture()
                    console.print(inner_table)
                    inner_dict[key] = console.end_capture()
                elif val and tablefmt == "tabulate" and hasattr(val[0], 'keys'):
                    inner_table = tabulate(val, headers="keys", tablefmt=tablefmt)
                    inner_dict[key] = inner_table
                else:
                    if all(isinstance(v, str) for v in val):
                        inner_dict[key] = ", ".join(val)
        out.append(inner_dict)
    return out

def tabulate_output(outdata: List[dict]) -> tuple:
    customer_id = customer_name = ""
    outdata = utils.listify(outdata)

    # -- // List[dict, ...] \\ --
    if outdata and all(isinstance(x, dict) for x in outdata):
        customer_id = outdata[0].get("customer_id", "")
        customer_name = outdata[0].get("customer_name", "")
        outdata = [{k: v for k, v in d.items() if k not in CUST_KEYS} for d in outdata]
        raw_data = outdata

        outdata = _do_subtables(outdata, tablefmt="tabulate")

        table_data = tabulate.tabulate(outdata, headers="keys", tablefmt="tabulate")
        td = table_data.splitlines(keepends=True)
        if td:
            table_data = f"{typer.style(td[0], fg='cyan')}{''.join(td[1:])}"

        data_header = f"--\n{'Customer ID:':15}{customer_id}\n" \
                        f"{'Customer Name:':15} {customer_name}\n--\n"
        table_data = f"{data_header}{table_data}" if customer_id else f"{table_data}"
        raw_data = f"{data_header}{raw_data}" if customer_id else f"{raw_data}"
    else:
        raw_data = table_data = outdata

    return raw_data, table_data

def rich_output(
    outdata: List[dict],
    title: str = None,
    caption: str = None,
    set_width_cols: dict = None,
    full_cols: Union[List[str], str] = [],
    fold_cols: Union[List[str], str] = [],
) -> tuple:
    """Render string formatted with rich/table

    Args:
        outdata (List[dict]): The output data to format
        title (str, optional): Table Title. Defaults to None.
        caption (str, optional): Table Caption. Defaults to None.
        account (str, optional): The account (displayed in caption if not the default). Defaults to None.
        set_width_cols (dict, optional): cols that need to be rendered with a specific width. Defaults to None.
        full_cols (Union[List[str], str], optional): cols that should not be truncated. Defaults to [].
        fold_cols (Union[List[str], str], optional): cols that can be folded (wrapped). Defaults to [].

    Returns:
        tuple: raw_data, table_data
    """
    console = Console(record=True, emoji=False)

    # -- // List[dict, ...] \\ --
    if outdata and all(isinstance(x, dict) for x in outdata):
        outdata = [{k: v for k, v in d.items() if k not in CUST_KEYS} for d in outdata]

        table = Table(
            show_header=True,
            title=title,
            header_style='magenta',
            show_lines=False,
            box=HORIZONTALS,
            row_styles=['none', 'dark_sea_green']
        )

        fold_cols = [*fold_cols, *RICH_FOLD_COLS]

        _min_max = {'min': 10, 'max': 30}
        if not set_width_cols:
            set_width_cols = {'name': _min_max, 'model': _min_max}
        else:
            for col, value in set_width_cols.items():
                if isinstance(value, int):  # allow simply specifying max width
                    set_width_cols[col] = {"max": value}

        full_cols = [*full_cols, *RICH_FULL_COLS]

        for k in outdata[0].keys():
            if k in fold_cols:
                table.add_column(k, overflow='fold', max_width=115, justify='left')
            elif k in set_width_cols:
                table.add_column(
                    k, min_width=set_width_cols[k].get('min', 0),
                    max_width=set_width_cols[k]['max'],
                    justify='left'
                )
            elif k in full_cols:
                table.add_column(k, no_wrap=True, justify='left')
            else:
                table.add_column(k, justify='left')

        formatted = _do_subtables(outdata)
        [table.add_row(*list(in_dict.values())) for in_dict in formatted]

        if title:
            table.title = f'[italic cornflower_blue]{title}[/]'
        if caption:
            table.caption_justify = 'left'
            table.caption = f"{caption.lstrip()}"


        console.begin_capture()
        console.print(table)
        table_data = console.end_capture()

        # rich is adding empty lines (full of spaces) to output on show clients, not sure why.  This will remove them
        # it appears they are lines with just ascii formmating, but no real text.
        table_data = "".join([line for line in str(table_data).splitlines(keepends=True) if typer.unstyle(line).strip()])
        raw_data = typer.unstyle(table_data)

        return raw_data, table_data

    return outdata, outdata

def output(
    outdata: Union[List[str], Dict[str, Any]],
    tablefmt: str = "rich",
    title: str = None,
    caption: str = None,
    account: str = None,
    config: Config = None,
    set_width_cols: dict = None,
    full_cols: Union[List[str], str] = [],
    fold_cols: Union[List[str], str] = [],
) -> Output:
    # log.debugv(f"data passed to output():\n{pprint(outdata, indent=4)}")
    raw_data = outdata
    _lexer = table_data = None

    if config and config.sanitize and raw_data and all(isinstance(x, dict) for x in raw_data):
        outdata = [{k: d[k] if k not in REDACT else "--redacted--" for k in d} for d in raw_data]

    # -- // List[str, ...] \\ --  Bypass all formatters, (config file output, etc...)
    if outdata and all(isinstance(x, str) for x in outdata):
        tablefmt = "strings"

    # -- convert List[dict] --> Dict[dev_name: dict] for yaml/json outputs
    if tablefmt in ['json', 'yaml', 'yml']:
        outdata = utils.listify(outdata)
        if outdata and isinstance(outdata[0], dict) and 'name' in outdata[0]:
            outdata: Dict[dict] = {
                item['name']: {k: v for k, v in item.items() if k != 'name'}
                for item in outdata
            }

    if tablefmt == "json":
        outdata = utils.unlistify(outdata)
        console = Console(record=True, emoji=False)
        console.begin_capture()
        console.print_json(json.dumps(outdata, cls=Encoder))
        table_data = console.end_capture()
        console.begin_capture()
        console.print('[bright_red]"Down"[/],')
        red_down = console.end_capture()
        table_data = table_data.replace('\x1b[32m"Down"\x1b[0m,\n', red_down)
        raw_data = typer.unstyle(table_data)

    elif tablefmt in ["yml", "yaml"]:
        outdata = utils.unlistify(outdata)
        # TODO custom yaml Representer
        raw_data = yaml.dump(json.loads(json.dumps(outdata, cls=Encoder)), sort_keys=False)
        table_data = rich_capture(raw_data)

    elif tablefmt == "csv":
        csv_data = "\n".join(
                        [
                            ",".join(
                                [
                                    str(v) if "," not in str(v) else f'"{v}"' for k, v in d.items() if k not in CUST_KEYS
                                ]
                            )
                            for d in outdata
                        ]
        )
        raw_data = table_data = csv_data if not outdata else f"{','.join([k for k in outdata[0].keys() if k not in CUST_KEYS])}\n{csv_data}\n"

    elif tablefmt == "rich":
        raw_data, table_data = rich_output(outdata, title=title, caption=caption, set_width_cols=set_width_cols, full_cols=full_cols, fold_cols=fold_cols)
        ...

    elif tablefmt == "tabulate":
        raw_data, table_data = tabulate_output(outdata)

    else:  # strings output No formatting
        # -- // List[str, ...] \\ --
        if len(outdata) == 1:
            if "\n" not in outdata[0]:
                # we can format green as only success output is sent through formatter.
                table_data = typer.style(f"  {outdata[0]}", fg="green")
                raw_data = outdata[0]
            else:  # template / config file output
                # get rid of double nl @ EoF (configs)
                if "\x1b" in outdata[0]:  # already styled (cass_output)
                    raw_data = typer.unstyle("{}\n".format('\n'.join(outdata).rstrip('\n')))
                    table_data = "{}\n".format('\n'.join(outdata).rstrip('\n'))
                else:
                    raw_data = table_data = "{}\n".format('\n'.join(outdata).rstrip('\n'))
                    table_data = rich_capture(raw_data)

        else:
            raw_data = table_data = '\n'.join(outdata)
            # Not sure what hit's this, but it was created so something must
            log.debug("List[str] else hit")

    if _lexer and raw_data:
        table_data = highlight(bytes(raw_data, 'UTF-8'),
                                _lexer(),
                                formatters.Terminal256Formatter(style='solarized-dark')
                                )

    if isinstance(raw_data, str):  # HACK
        raw_data = raw_data.replace('✅', 'True').replace('❌', 'False')   #  TODO handle this better messes up column spacing if replacing string.

    return Output(rawdata=raw_data, prettydata=table_data, config=config)


def rich_capture(text: str | List[str], emoji: bool = False, **kwargs) -> str:
    """Accept text or list of text with rich markups and return final colorized text with ascii control chars

    This is temporary as the rich context handler stopped working.  Can revert once fixed upstream

    Args:
        text (str | List[str]): The text or list of text to capture.
            If provided as list it will be converted to string (joined with \n)

    Returns:
        str: text with markups converted to ascii control chars
    """
    if isinstance(text, list):
        "\n".join(text)
    console = Console(record=True, emoji=emoji, **kwargs)
    console.begin_capture()
    console.print(text)
    out = console.end_capture()
    return out if len(out.splitlines()) > 1 else out.rstrip("\n")
