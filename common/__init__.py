# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
from typing import List
import urllib3
import requests
# from .config import Config
from sys import argv
from pathlib import Path
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# PROMPT = re.compile(r"([a-zA-Z0-9\-.\s]*#)")

console = Console()
econsole = Console(stderr=True)

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}


class Response():
    def __init__(self, ok: bool, output=None, error=None, status_code=None, state=None,  **kwargs):
        self.ok = ok
        self.text = output
        self.error = error
        self.state = state
        self.status_code = status_code
        if 'json' in kwargs:
            self.json = kwargs['json']
        else:
            self.json = None


class AosConnect(Response):

    def __init__(self, ip: str, user: str = '', password: str = '', port: int = 4343):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.handle = None
        self.output = ''

    def api_login(self) -> object:
        """
        This function will login into the controller using API.
        :return: connection handle for the device.
        """

        url = f"https://{self.ip}:{self.port}/v1/api/login"
        payload = {'username': self.user, 'password': self.password}

        if self.ip:
            try:
                r = requests.post(url, data=payload, headers=headers, verify=False)
                self.handle = r
                return Response(ok=True, output=r.text, json=r.json(), status_code=r.status_code)
            except Exception as err:
                return Response(ok=False, error=err)
        else:
            return Response(ok=False, error="No IP address")

    def execute_command(self, cmd: str) -> object:
        """
        This function will execute commands on controller and returns the output
        :param cmd: command to be executed on device
        :return: data containing output of the command
        """
        try:
            parameters = {"UIDARUBA": self.handle.headers['Set-Cookie'].split(';')[0].split('=')[1], "command": cmd}
            r = requests.get(f"https://{self.ip}:{self.port}/v1/configuration/showcommand",
                             verify=False,
                             headers=headers,
                             params=parameters, cookies=self.handle.cookies
                             )
            if r.ok:
                return Response(ok=True, output=r.text, status_code=r.status_code, json=r.json())
            else:
                return Response(ok=False, error=r.reason, status_code=r.status_code)
        except Exception as err:
            return Response(ok=False, error=err)


class MyLogger:
    def __init__(self, log_file: str | Path, debug: bool = False, show: bool = False):
        self.log_msgs: List[str] = []
        self.DEBUG = debug
        self.verbose = False
        if isinstance(log_file, Path):
            self.log_file = log_file
        else:
            self.log_file = Path(log_file)
        self._log = self.get_logger()
        self.name = self._log.name
        self.show = show  # Sets default log behavior (other than debug)

    def get_logger(self):
        '''Return custom log object.'''
        fmtStr = "%(asctime)s [%(process)d][%(levelname)s]: %(message)s"
        dateStr = "%m/%d/%Y %I:%M:%S %p"
        logging.basicConfig(filename=self.log_file.absolute(),
                            level=logging.DEBUG if self.DEBUG else logging.INFO,
                            format=fmtStr,
                            datefmt=dateStr)
        return logging.getLogger(self.log_file.stem)

    @staticmethod
    def _remove_rich_markups(log_msg: str) -> str:
        if "[/" not in log_msg:
            return log_msg

        console = Console(force_terminal=False)
        with console.capture() as cap:
            console.print(log_msg, end="")

        return cap.get()

    def log_print(self, msgs, log=False, show=True, level='info', *args, **kwargs):
        msgs = [msgs] if not isinstance(msgs, list) else msgs
        _msgs = []
        _logged = []

        for i in msgs:
            i = str(i)
            if i not in _logged:
                if log:
                    getattr(self._log, level)(self._remove_rich_markups(i), *args, **kwargs)
                    _logged.append(i)
                if i and i not in self.log_msgs:
                    _msgs.append(i)

        if show is not False and True in [show, self.show]:
            self.log_msgs += _msgs
            for m in self.log_msgs:
                if console.is_terminal:
                    _pfx = '' if not self.DEBUG else '\n'  # Add a CR before showing log when in debug due to spinners
                    warning_emoji = "[dark_orange3]\u26a0[/]  "
                    econsole.print(f"{_pfx}{warning_emoji if level not in ['info', 'debug'] else ''}{m}", emoji=":cd:" not in m.lower())  # avoid :cd: emoji common in mac addresses

            self.log_msgs = []

    def show(self, msgs: list | str, log: bool = False, show: bool = True, *args, **kwargs) -> None:
        self.log_print(msgs, show=show, log=log, *args, **kwargs)

    def debug(self, msgs: list | str, log: bool = True, show: bool = False, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, level='debug', *args, **kwargs)

    # -- more verbose debugging
    def debugv(self, msgs: list | str, log: bool = True, show: bool = False, *args, **kwargs) -> None:
        if self.DEBUG and self.verbose:
            self.log_print(msgs, log=log, show=show, level='debug', *args, **kwargs)

    def info(self, msgs: list | str, log: bool = True, show: bool = None, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, *args, **kwargs)

    def warning(self, msgs: list | str, log: bool = True, show: bool = None, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, level='warning', *args, **kwargs)

    def error(self, msgs: list | str, log: bool = True, show: bool = None, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, level='error', *args, **kwargs)

    def exception(self, msgs: list | str, log: bool = True, show: bool = None, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, level='exception', *args, **kwargs)

    def critical(self, msgs: list | str, log: bool = True, show: bool = None, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, level='critical', *args, **kwargs)

    def fatal(self, msgs: list | str, log: bool = True, show: bool = None, *args, **kwargs) -> None:
        self.log_print(msgs, log=log, show=show, level='fatal', *args, **kwargs)

    def setLevel(self, level):
        getattr(self._log, 'setLevel')(level)


_calling_script = Path(argv[0])
log_file = _calling_script.joinpath(_calling_script.resolve().parent, "logs", f"{_calling_script.stem}.log")

# config = Config()
log = MyLogger(log_file, show=True)
