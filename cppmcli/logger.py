from os import environ
from pathlib import Path
from typing import Union
from logging.handlers import RotatingFileHandler
from time import sleep
from rich.console import Console

import logging
import typer


log_colors = {
    "error": typer.colors.RED,
    "exception": typer.colors.RED,
    "critical": typer.colors.RED,
    "fatal": typer.colors.RED,
    "warning": typer.colors.YELLOW,
}
# log_colors = {
#     "error": "[bright_red]",
#     "exception": "[bright_red]",
#     "critical": "[bright_red]",
#     "fatal": "[bright_red]",
#     "warning": "[dark_orange4]",
# }
console = Console(emoji=False, markup=False)
to_debug = [
    "Loaded token from storage from file"
]


class MyLogger:
    def __init__(self, log_file: Union[str, Path], debug: bool = False, show: bool = False, verbose: bool = False):
        self._DEBUG = debug
        self.log_msgs = []
        self.verbose = verbose
        if isinstance(log_file, Path):
            self.log_file = log_file
        else:
            self.log_file = Path(log_file)
        self._log = self.get_logger()
        self.name = self._log.name
        self.show = show  # Sets default log behavior (other than debug)

    def __getattr__(self, name: str):
        if hasattr(self, "_log") and hasattr(self._log, name):
            return getattr(self._log, name)
        else:
            raise AttributeError(f"'MyLogger' object has no attribute '{name}'")

    def get_logger(self) -> logging.Logger:
        '''Return custom log object.'''
        fmtStr = "%(asctime)s [%(process)d][%(levelname)s]: %(message)s"
        # fmtStr = "%(asctime)s [%(process)d][%(levelname)s]{%(pathname)s:%(lineno)d}: %(message)s"
        dateStr = "%m/%d/%Y %I:%M:%S %p"
        # fmtStr = "%(message)s"
        # dateStr = "[%X]"
        logging.basicConfig(
            # filename=self.log_file.absolute(),
            level=logging.DEBUG if self.DEBUG else logging.INFO,
            format=fmtStr,
            datefmt=dateStr,
            handlers=[
                # RichHandler(rich_tracebacks=True, tracebacks_show_locals=True, show_path=False),
                RotatingFileHandler(self.log_file.absolute(),  maxBytes=250000, backupCount=5,),
            ],
        )
        return logging.getLogger(self.log_file.stem)

    def print_file(self):
        console.print(self.log_file.read_text(),)

    def follow(self):
        '''generator function that yields new lines in log file
        '''
        with self.log_file.open("r") as lf:
            lines = lf.readlines()
            console.print("".join(lines[int(f"-{len(lines) if len(lines) <= 20 else 20}"):]).rstrip())

            while True:
                try:
                    line = lf.readline()
                    if not line:
                        sleep(1)
                        continue

                    console.print(line.rstrip())
                except (KeyboardInterrupt, EOFError):
                    break

    def log_print(self, msgs, log: bool = False, show: bool = False, level: str = 'info', *args, **kwargs):
        # TODO can prob remove log_msgs, used by another project I re-used this object from (ConsolePi)
        msgs = [msgs] if not isinstance(msgs, list) else msgs
        _msgs = []
        _logged = []
        for i in msgs:
            i = str(i)
            if not self.DEBUG and [i for d in to_debug if d in i]:
                continue

            if log and i not in _logged:
                getattr(self._log, level)(i, *args, **kwargs)
                _logged.append(i)
                if i and i not in self.log_msgs:
                    _msgs.append(i)

        if show is not False and True in [show, self.show]:
            self.log_msgs += _msgs
            for m in self.log_msgs:
                if console.is_terminal or environ.get("PYTEST_CURRENT_TEST"):
                    typer.secho(m, fg=log_colors.get(level))
            self.log_msgs = []

    @property
    def level_name(self):
        return logging.getLevelName(self._log.level)

    @property
    def DEBUG(self):
        return self._DEBUG

    @DEBUG.setter
    def DEBUG(self, value: bool = False):
        self._DEBUG = value
        self.show = value
        self.setLevel(logging.DEBUG if value else logging.INFO)

    def show(self, msgs: Union[list, str], log: bool = False, show: bool = True, *args, **kwargs) -> None:
        self.log_print(msgs, show=show, log=log, *args, **kwargs)

    def debug(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, level='debug', *args, **kwargs)

    def debugv(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        """more verbose debugging - primarily to get json dumps, set via debugv: True in config
        """
        # show = show or self.show
        if self.DEBUG and self.verbose:
            self.log_print(msgs, log=log, show=show, level='debug', *args, **kwargs)

    def info(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, *args, **kwargs)

    def warning(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, level='warning', *args, **kwargs)

    def error(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, level='error', *args, **kwargs)

    def exception(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, level='exception', *args, **kwargs)

    def critical(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, level='critical', *args, **kwargs)

    def fatal(self, msgs: Union[list, str], log: bool = True, show: bool = None, *args, **kwargs) -> None:
        # show = show or self.show
        self.log_print(msgs, log=log, show=show, level='fatal', *args, **kwargs)

    def setLevel(self, level):
        getattr(self._log, 'setLevel')(level)
