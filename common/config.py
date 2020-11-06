#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss

from pathlib import Path
from typing import Any
import yaml


class Config:
    def __init__(self):
        BASE_DIR = Path(__file__).parent.parent
        yaml_config = BASE_DIR.joinpath('config.yaml')
        self.config = self.get_yaml_file(yaml_config) or {}
        self.DEBUG = self.config.get("debug", False)

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
