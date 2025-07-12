import os
import sys
import typer
import json

from pathlib import Path


# if no environ vars set for LESS command line options
# set -X to retain scroll-back after quitting less
#     -R for color output (default for the pager but defaults are not used if LESS is set)
#     +G so (start with output scrolled to end) so scroll-back contains all contents
# if not os.environ.get("LESS"):
os.environ["LESS"] = "-RX +G"

import click

from rich.traceback import install
install(show_locals=True, suppress=[click])

_calling_script = Path(sys.argv[0])
if str(_calling_script) == "." and os.environ.get("TERM_PROGRAM") == "vscode":
    _calling_script = Path.cwd() / "cli.py"   # vscode run in python shell

app_dir = Path(typer.get_app_dir(__name__))
if _calling_script.name == "cppm" or app_dir.exists():
    base_dir = app_dir
elif _calling_script.name.startswith("test_"):
    base_dir = _calling_script.parent.parent
elif "cppmcli" in Path(__file__).parts:
    base_dir = Path(__file__).parent
    while base_dir.name != "cppmcli":
        base_dir = base_dir.parent
    base_dir = base_dir.parent
else:
    base_dir = _calling_script.resolve().parent
    if base_dir.name == "cppmcli":
        base_dir = base_dir.parent
    else:
        print("Warning Logic Error in git/pypi detection")
        print(f"base_dir Parts: {base_dir.parts}")

from .logger import MyLogger  #NoQA
from .config import Config  # NoQA
config = Config(base_dir=base_dir)

log_dir = config.base_dir / "logs"
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / f"{__name__}.log"

if '--debug' in str(sys.argv) or os.environ.get("ARUBACLI_DEBUG", "").lower() in ["1", "true"]:
    config.debug = True  # for the benefit of the 2 log messages below
if '--debugv' in str(sys.argv):
    config.debug = config.debugv = True
    try:
        _ = sys.argv.pop(sys.argv.index("--debugv"))
    except ValueError:
        # handles vscode issue as arg parsing for vscode is below
        sys.argv = [arg.replace("--debugv", "").rstrip().replace("  ", " ") for arg in sys.argv]

log = MyLogger(log_file, debug=config.debug, show=config.debug, verbose=config.debugv)

log.debug(f"{__name__} __init__ calling script: {_calling_script}, base_dir: {config.base_dir}")
log.debugv(f"config attributes: {json.dumps({k: str(v) for k, v in config.__dict__.items()}, indent=4)}")

from .utils import Utils  # NoQA
utils = Utils()
from .clicommon import CLICommon  #NoQA

if os.environ.get("TERM_PROGRAM") == "vscode":
    from .vscodeargs import vscode_arg_handler
    vscode_arg_handler()

raw_out = False
if "-vv" in sys.argv:
    raw_out = True
    _ = sys.argv.pop(sys.argv.index("-vv"))
if "--debug-limit" in sys.argv:
    _idx = sys.argv.index("--debug-limit")
    _ = sys.argv.pop(sys.argv.index("--debug-limit"))
    if len(sys.argv) - 1 >= _idx and sys.argv[_idx].isdigit():
        config.limit = int(sys.argv[_idx])
        _ = sys.argv.pop(_idx)
    else:
        print(f"Invalid Value ({sys.argv[_idx]}) for --debug-limit expected an int")
        sys.exit(1)

cli = CLICommon(config=config, logger=log, raw_out=raw_out)

# allow singular form and common synonyms for the defined show commands
# show switches / show switch ...
# if len(sys.argv) > 2:
#     sys.argv[2] = constants.arg_to_what(sys.argv[2], cmd=sys.argv[1])

if "?" in sys.argv:
    sys.argv[sys.argv.index("?")] = "--help"