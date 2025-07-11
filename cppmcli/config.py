#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
from pathlib import Path
from typing import Any
from rich import print
import sys
import yaml
from typing import Dict


class Config:
    def __init__(self, base_dir: Path = Path(__file__).parent.parent):
        self.base_dir = base_dir
        self.cwd = Path().cwd()
        if Path.joinpath(self.cwd, "out").is_dir():
            self.outdir = self.cwd / "out"
        else:
            self.outdir = self.cwd
        self.file = self.base_dir / 'config.yaml'
        if not self.file.exists():
            print(f":warning:  Config file {self.file} not found.")
            config = {}
        else:
            self.dir = self.base_dir
            self.cache_dir = self.dir / ".cache"
            self.cache_dir.mkdir(exist_ok=True)
            config = self.get_yaml_file(self.file) or {}

        self.config: Dict[str, str | Dict[str, str]] = config.get("CPPM") or config.get("cppm", {})
        self.debug = self.config.get("debug", False)
        self.debugv = self.config.get("debugv", False)
        self.fqdn = self.config.get("fqdn")
        self.client_id = self.config.get("client_id")
        self.client_secret = self.config.get("client_secret")
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.grant_type = self.config.get("grant_type", "client_credentials")
        self.username = self.config.get("username")
        self.password = self.config.get("password")
        self.sanitize = False
        self.cache_dir = self.dir / ".cache"
        self.last_command_file = self.cache_dir / "last_command"
        if not self.ok:
            _missing = '[bright_red italic]Missing[/]'
            print(f":warning:  Invalid Configuration, [cyan]fqdn[/]: {f'[bright_green]{self.fqdn}[/]' if self.fqdn else _missing}, [cyan]client_id[/]: {f'[bright_green]{self.client_id}[/]' if self.client_id else _missing} and [cyan]client_secret[/]: {'[bright_green]*****[/]' if self.client_secret else _missing} are all required")
            sys.exit(1)

    @property
    def ok(self):
        return not any([s is None for s in [self.fqdn, self.client_id, self.client_secret]])

    def __bool__(self):
        return len(self.config) > 0

    def __len__(self):
        return len(self.config)

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    @staticmethod
    def get_yaml_file(yaml_config: Path):
        '''Return dict from yaml file.'''
        if yaml_config.exists() and yaml_config.stat().st_size > 0:
            with yaml_config.open() as f:
                try:
                    return yaml.load(f, Loader=yaml.SafeLoader)
                except ValueError as e:
                    print(f'Unable to load configuration from {yaml_config}\n\t{e}')
