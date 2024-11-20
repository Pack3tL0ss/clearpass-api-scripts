"""object Classes"""

from __future__ import annotations

from typing import Literal
from json import JSONEncoder
import pendulum
from pathlib import Path


TimeFormat = Literal["day-datetime", "durwords", "durwords-short", "timediff", "mdyt", "log"]

# class TimeFormat(str, Enum):
#     day_datetime = "day-datetime"
#     durwords = "durwords"
#     durwords_short = "durwords-short"
#     timediff = "timediff"
#     mydt = "mydt"
#     log = "log"

def _convert_epoch(epoch: float) -> str:
    """Thu, May 7, 2020 3:49 AM"""
    return pendulum.from_timestamp(epoch, tz="local").to_day_datetime_string()


def _log_timestamp(epoch: float) -> str:
    """Jan 08 7:59:00 PM"""
    if isinstance(epoch, str):
        try:
            epoch = float(epoch)
        except TypeError:
            return epoch

    return pendulum.from_timestamp(epoch, tz="local").format("MMM DD h:mm:ss A")


def _mdyt_timestamp(epoch: float) -> str:
    """May 07, 2020 3:49:24 AM"""
    return pendulum.from_timestamp(epoch, tz="local").format("MMM DD, YYYY h:mm:ss A")


def _duration_words(secs: int | str) -> str:
    """2 weeks 1 day 1 hour 21 minutes 2 seconds"""
    return pendulum.duration(seconds=int(secs)).in_words()


def _duration_words_short(secs: int | str) -> str:
    """2w 1d 1h 21m 2s"""
    words = pendulum.duration(seconds=int(secs)).in_words()
    # a bit cheesy, but didn't want to mess with regex
    replace_words = [
        (" years", "y"),
        (" year", "y"),
        (" weeks", "w"),
        (" week", "w"),
        (" days", "d"),
        (" day", "d"),
        (" hours", "h"),
        (" hour", "h"),
        (" minutes", "m"),
        (" minute", "m"),
        (" seconds", "s"),
        (" second", "s"),
    ]
    for orig, short in replace_words:
        words = words.replace(orig, short)
    return words


def _time_diff_words(epoch: float | None) -> str:
    """47 minutes ago"""
    return "" if epoch is None else pendulum.from_timestamp(epoch, tz="local").diff_for_humans()


TIME_FUNCS = {
    "day-datetime": _convert_epoch,
    "durwords": _duration_words,
    "durwords-short": _duration_words_short,
    "timediff": _time_diff_words,
    "mdyt": _mdyt_timestamp,
    "log": _log_timestamp
}

class DateTime():
    def __init__(self, epoch: int | float, format: TimeFormat = "day-datetime") -> None:
        self.epoch = self.normalize_epoch(epoch)
        self.pretty = TIME_FUNCS[format](self.epoch)

    def normalize_epoch(self, epoch: int | float) -> int | float:
        if str(epoch).isdigit() and len(str(int(epoch))) > 10:
            epoch = epoch / 1000

        return epoch if not str(epoch).endswith(".0") else int(epoch)

    def __str__(self):
        return self.pretty

    def __bool__(self):
        return self.epoch and self.epoch > 0

    def __len__(self) -> int:
        return len(self.epoch)

    def __lt__(self, other) -> bool:
        return self.epoch < other

    def __le__(self, other) -> bool:
        return self.epoch <= other

    def __eq__(self, other) -> bool:
        return self.epoch == other

    def __gt__(self, other) -> bool:
        return self.epoch > other

    def __ge__(self, other) -> bool:
        return self.epoch >= other


class Encoder(JSONEncoder):
    """
    A Custom JSON Encoder to handle custom DateTime object during JSON serialization.
    """
    def default(self, o):
        return o if not isinstance(o, DateTime) and not isinstance(o, Path) else str(o)

