#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Collection of functions used to clean output from Aruba Central API into a consistent structure.
"""
from __future__ import annotations

import functools
import ipaddress
import logging
import sys
import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Union

import pendulum
from rich.console import Console
from rich.markup import escape

# Detect if called from pypi installed package or via cloned github repo (development)
try:
    from cppmcli import constants, log, utils
except (ImportError, ModuleNotFoundError) as e:
    pkg_dir = Path(__file__).absolute().parent
    if pkg_dir.name == "centralcli":
        sys.path.insert(0, str(pkg_dir.parent))
        from cppmcli import constants, log, utils
    else:
        print(pkg_dir.parts)
        raise e

from cppmcli.constants import DevTypes
from cppmcli.objects import DateTime


def epoch_convert(func):
    @functools.wraps(func)
    def wrapper(epoch):
        if str(epoch).isdigit() and len(str(int(epoch))) > 10:
            epoch = epoch / 1000
        return func(epoch)

    return wrapper


# show certificates
def _convert_datestring(date_str: str) -> str:
    return pendulum.from_format(date_str.rstrip("Z"), "YYYYMMDDHHmmss").to_formatted_date_string()


# show fw list
def _convert_iso_to_words(iso_date: str) -> str:
    return pendulum.parse(iso_date).to_formatted_date_string()


@epoch_convert
def _convert_epoch(epoch: float) -> str:
    # Thu, May 7, 2020 3:49 AM
    return pendulum.from_timestamp(epoch, tz="local").to_day_datetime_string()


@epoch_convert
def _duration_words(secs: Union[int, str]) -> str:
    return pendulum.duration(seconds=int(secs)).in_words()


@epoch_convert
def _duration_words_short(secs: Union[int, str]) -> str:
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


@epoch_convert
def _time_diff_words(epoch: float | None) -> str:
    return "" if epoch is None else pendulum.from_timestamp(epoch, tz="local").diff_for_humans()


@epoch_convert
def _log_timestamp(epoch: float) -> str:
    if isinstance(epoch, str):
        try:
            epoch = float(epoch)
        except TypeError:
            return epoch

    return pendulum.from_timestamp(epoch, tz="local").format("MMM DD h:mm:ss A")


@epoch_convert
def _mdyt_timestamp(epoch: float) -> str:
    # May 07, 2020 3:49:24 AM
    return pendulum.from_timestamp(epoch, tz="local").format("MMM DD, YYYY h:mm:ss A")



def _short_connection(value: str) -> str:
    return "" if value is None else value.replace("802.11", "")


def _serial_to_name(sernum: str) -> str:
    # TODO circular import if placed at top review import logic
    from cppmcli import cache
    if not (
        len(sernum) in (9, 10) and all([s.isalpha() for s in sernum[0:2]]) and all([s.isupper() for s in sernum.split()])
    ):
        return sernum

    match = cache.get_dev_identifier(sernum, retry=False, silent=True)
    if not match:
        return sernum

    return match.name


def _get_dev_name_from_mac(mac: str, dev_type: str | List[str] = None, summary_text: bool = False) -> str:
    if mac.count(":") != 5:
        return mac
    else:
        # TODO circular import if placed at top review import logic
        from cppmcli import cache
        match = cache.get_dev_identifier(mac, dev_type=dev_type, retry=False, silent=True)
        if not match:
            return mac

        match = utils.unlistify(match)

        if isinstance(match, list) and len(match) > 1:
            return mac

        return match.name if not summary_text else f'{match.name}|{match.ip}|Site: {match.site}'


def _extract_names_from_id_name_dict(id_name: dict) -> str:
    if isinstance(id_name, dict) and "id" in id_name and "name" in id_name:
        names = [x.get("name", "Error") for x in id_name]
        return ", ".join(names)
    else:
        return id_name


def _extract_event_details(details: List[dict]) -> dict:
    data = {
        k: v for k, v in [tuple(short_value(k, v)) for d in details for k, v in d.items()]
    }
    return "\n".join([f"{k}: {v}" for k, v in data.items()])


def _format_memory(mem: int) -> str:
    # gw and aps report memory in bytes
    #
    gmk = [(1_073_741_824, "GB"), (1_048_576, "MB"), (1024, "KB")]
    if len(str(mem)) > 4:
        for divisor, indicator in gmk:
            if mem / divisor > 1:
                return f'{round(mem / divisor, 2)} {indicator}'

    return f'{mem}'

_NO_FAN = ["Aruba2930F-8G-PoE+-2SFP+ Switch(JL258A)"]

# TODO determine all modes possible (CX)
vlan_modes = {
    1: "Access",
    3: "Trunk",
}

_short_value = {
    "Aruba, a Hewlett Packard Enterprise Company": "HPE/Aruba",
    "No Authentication": "open",
    "last_connection_time": _time_diff_words,
    "uptime": lambda x: DateTime(x, "durwords-short"),
    "updated_at": lambda x: DateTime(x, "mdyt"),
    "last_modified": _convert_epoch,
    "lease_start_ts": _log_timestamp,
    "lease_end_ts": _log_timestamp,
    "create_date": _convert_iso_to_words,
    "acknowledged_timestamp": _log_timestamp,
    "lease_time": _duration_words,
    "lease_time_left": _duration_words,
    "token_created": lambda x: DateTime(x, "mdyt"),
    "ts": lambda x: DateTime(x, format="log"),  # _log_timestamp,
    "timestamp": lambda x: DateTime(x, format="log"),
    "Unknown": "?",
    "HPPC": "SW",
    "labels": _extract_names_from_id_name_dict,
    "sites": _extract_names_from_id_name_dict,
    "ACCESS POINT": "AP",
    "GATEWAY": "GW",
    # "events_details": _extract_event_details,
    "vc_disconnected": "vc disc.",
    "MAC Authentication": "MAC",
    "connection": _short_connection,
    "DOT1X": ".1X",
    "target": _serial_to_name,
    "0.0.0.0": "-",
    "free_ip_addr_percent": lambda x: f"{x}%",
    "cpu_utilization": lambda x: f"{x}%",
    "AOS-CX": "cx",
    "type": lambda t: t.lower(),
    "release_status": lambda v: u"\u2705" if "beta" in v.lower() else "",
    "start_date": _mdyt_timestamp,
    "end_date": _mdyt_timestamp,
    "start_time": _mdyt_timestamp,
    "create_time": _mdyt_timestamp,
    "expire_time": lambda ts: _mdyt_timestamp(ts) or "Never",
    "auth_type": lambda v: v if v != "None" else "-",
    "vlan_mode": lambda v: vlan_modes.get(v, v),
    "allowed_vlan": lambda v: v if not isinstance(v, list) or len(v) == 1 else ",".join([str(sv) for sv in sorted(v)]),
    "mem_total": _format_memory,
    "mem_free": _format_memory,
    "firmware_version": lambda v: v if len(set(v.split("-"))) == len(v.split("-")) else "-".join(v.split("-")[1:]),
    "learn_time": _log_timestamp,
    "last_state_change": _log_timestamp,
    "graceful_restart_timer": _duration_words,
    "disable_ssid": lambda v: '✅' if not v else '❌', # field is changed to "enabled" check: \u2705 x: \u274c
    "mac": lambda mac: utils.Mac(mac).cols
    # "enabled": lambda v: not v, # field is changed to "enabled"
    # "allowed_vlan": lambda v: str(sorted(v)).replace(" ", "").strip("[]")
}

_short_key = {
    "interface_port": "interface",
    "firmware_version": "version",
    "firmware_backup_version": "backup version",
    "group_name": "group",
    "public_ip_address": "public ip",
    "ip_address": "ip",
    "ip_addr": "ip",
    "ip_address_v6": "ip (v6)",
    "macaddr": "mac",
    "switch_type": "type",
    "uplink_ports": "uplk ports",
    "total_clients": "clients",
    "updated_at": "updated",
    "cpu_utilization": "cpu %",
    "mem_pct": "mem %",
    "app_name": "app",
    "device_type": "type",
    "classification": "class",
    "ts": "time",
    "timestamp": "time",
    "ap_deployment_mode": "mode",
    "authentication_type": "auth",
    "last_connection_time": "last connected",
    "connection": "802.11",
    "user_role": "role",
    "lease_start_ts": "lease start",
    "lease_end_ts": "lease end",
    "lease_time_left": "lease remaining",
    "vlan_id": "pvid",
    "free_ip_addr_percent": "free ip %",
    "events_details": "details",
    "associated_device_count": "devices",
    "label_id": "id",
    "command_id": "id",
    "label_name": "name",
    # "acknowledged": "ack",
    "acknowledged_by": "ack by",
    "acknowledged_timestamp": "ack time",
    "aruba_part_no": "sku",
    "network": "ssid",
    "release_status": "beta",
    "license_type": "name",
    "subscription_key": "key",
    "subscription_type": "type",
    "capture_url": "url",
    "register_accept_email": "accept email",
    "register_accept_phone": "accept phone",
    "neighbor_id": "router id",
    "dr_address": "DR IP",
    "bdr_address": "BDR IP",
    "dr_id": "DR rtr id",
    "bdr_id": "BDR rtr id",
    "auth_type": "auth",
    "neighbor_count": "nbrs",
    "area_id": "area",
    "intf_state_down_reason": "Down Reason",
    "is_uplink": "Uplink",
    "client_count": "clients",
    "is_best": "best",
    "num_routes": "routes",
    "disable_ssid": "enabled",
    "mac_authentication": "mac auth",
    "hide_ssid": "hidden",
    "essid": "ssid",
    "opmode": "security",
}


def strip_outer_keys(data: dict) -> Union[list, dict]:
    """strip unnecessary wrapping key from API response payload

    Args:
        data (dict): The response payload (aiohttp.Response.json())

    Returns:
        Union[list, dict]: typically list of dicts
    """
    # return unaltered payload if payload is not a dict, or if it has > 5 keys (wrapping typically has 2 sometimes 3)
    if not isinstance(data, dict) or len([key for key in data.keys() if key not in ["cid", "status_code"]]) > 5:
        return data

    data = data if "result" not in data else data["result"]
    _keys = [k for k in constants.STRIP_KEYS if k in data]
    if len(_keys) == 1:
        return data[_keys[0]]
    elif _keys:
        print(f"More wrapping keys than expected from return {_keys}")
    return data


def pre_clean(data: dict) -> dict:
    if isinstance(data, dict):
        if data.get("fan_speed", "") == "Fail":
            if data.get("model", "") in _NO_FAN:
                data["fan_speed"] = "N/A"
    return data


# TODO moved to utils
def _unlist(data: Any):
    """Remove unnecessary outer lists.

    Returns:
        [] = ''
        ['single_item'] = 'single item'
        [[item1], [item2], ...] = [item1, item2, ...]
    """
    if isinstance(data, list):
        if not data:
            data = ""
        elif len(data) == 1:
            data = data[0] if not isinstance(data[0], str) else data[0].replace("_", " ")
        elif all([isinstance(d, list) and len(d) == 1 for d in data]):
            out = [i for ii in data for i in ii if not isinstance(i, list)]
            if out:
                data = out

    return data


def _check_inner_dict(data: Any) -> Any:
    if isinstance(data, list):
        if True in set([isinstance(id, dict) for id in data]):
            if list(set([dk for d in data for dk in d.keys()]))[0] == "port":
                return _unlist([d["port"] for d in data])
            else:
                return _unlist(
                    [dict(short_value(vk, vv) for vk, vv in pre_clean(inner).items() if vk != "index") for inner in data]
                )
    return data


def short_key(key: str) -> str:
    return _short_key.get(key, key.replace("_", " "))


def short_value(key: str, value: Any):
    # _unlist(value)
    # Run any inner dicts through cleaner funcs
    if isinstance(value, dict):
        value = {short_key(k): v if k not in _short_value else _short_value[k](v) for k, v in value.items()}

    if isinstance(value, (str, int, float)):
        return (
            short_key(key),
            _short_value.get(value, value) if key not in _short_value or (not isinstance(value, bool) and not value) else _short_value[key](value),
        )
    elif isinstance(value, list) and all(isinstance(x, dict) for x in value):
        if key in ["sites", "labels"]:
            value = _extract_names_from_id_name_dict(value)
        elif key in ["events_details"]:
            value = _extract_event_details(value)
    elif key in _short_value:
        value = _short_value[key](value)

    return short_key(key), _unlist(value)

def simple_kv_formatter(data: List) -> List:
    """Default simple formatter

    runs all key/values through _short_key, _short_value

    Args:
        data (List): Data typically a list of dicts

    Returns:
        List: Formatted data
    """
    if not isinstance(data, list):
        log.warning(f"cleaner.simple_kv_formatter expected a list but rcvd {type(data)}")
        return data

    data = [
        dict(
            short_value(
                k,
                v,
            )
            for k, v in d.items()
        )
        for d in data
    ]

    return data

def _get_group_names(data: List[List[str],]) -> list:
    """Convert list of single item lists to a list of strs

    Also removes "unprovisioned" group as it has no value for our
    purposes, and moves default group to beginning of list.

    Args:
        data (List[List[str],]): Central response payload

    Returns:
        list: List of strings with "unprovisioned" group removed
        and default moved to front.
    """
    groups = [g for _ in data for g in _ if g != "unprovisioned"]
    if "default" in groups:
        groups.insert(0, groups.pop(groups.index("default")))
    return groups


def get_all_groups(
    data: List[
        dict,
    ]
) -> list:
    """groups cleaner formats data for cache

    Args:
        data (List[ dict, ]): api response output from get_all_groups

    Returns:
        list: reformatted Data with keys/headers changed
    """
    # TODO use _short_key like others and combine show groups into this func
    _keys = {"group": "name", "template_details": "template group"}
    return [{_keys[k]: v for k, v in g.items()} for g in data]

def show_groups(data: List[dict]) -> List[dict]:
    return [{k: v if k != "template group" else ",".join([kk for kk, vv in v.items() if vv]) or "--" for k, v in inner.items()} for inner in data]

def get_labels(
    data: Union[List[dict,], Dict]
) -> list:
    data = utils.listify(data)
    data = [
        dict(
            short_value(
                k,
                d.get(k),
            )
            for k in d.keys()
            if not k.startswith("category_")
        )
        for d in data
        if d["category_id"] == 1
    ]
    data = strip_no_value(data)

    return data


def _client_concat_associated_dev(
    data: Dict[str, Any],
    verbose: bool = False,
    cache=None,
) -> Dict[str, Any]:
    if cache is None:
        from cppmcli import cache
    strip_keys = [
        "associated device",
        "associated device mac",
        "connected device type",
        "interface",
        "interface mac",
        "gateway serial",
    ]

    # FIXME get_dev_identifier can fail if client is connected to device that is not in the cache.
    # even with a cache update.  doing show all is fine, but update cache for whatever reason with this method
    # is causing some kind of SSL error, which results in cache lookup failure.
    # silent=True, retry=False, resolves.  Would need no_match OK as get_dev_identifier fails if no match.
    dev, _gw, data["gateway"] = "", "", {}
    if data.get("associated_device"):
        dev = cache.get_dev_identifier(data["associated_device"])

    if data.get("gateway_serial"):
        _gw = cache.get_dev_identifier(data["gateway_serial"])
        _gateway = {
            "name": _gw.name,
            "serial": data.get("gateway_serial", ""),
        }
        if verbose:
            data["gateway"] = _unlist(strip_no_value([_gateway]))
        else:
            data["gateway"] = _gw.name or data["gateway_serial"]
    _connected = {
        "name": data.get("associated_device") if not hasattr(dev, "name") else dev.name,
        "type": data.get("connected_device_type"),
        "serial": data.get("associated_device"),
        "mac": data.get("associated_device_mac"),
        "interface": data.get("interface_port"),
        "interface mac": data.get("interface_mac"),
    }
    for key in strip_keys:
        if key in data:
            del data[key]
    if verbose:
        data["connected device"] = _unlist(strip_no_value([_connected]))
    else:
        # More work than is prob warranted by if the device name includes the type, and the adjacent characters are
        # not alpha then we don't append the type.  So an ap with a name of Zrm-655-ap will not have (AP) appended
        # but Zrm-655-nap would have it appended
        data["connected device"] = f"{_connected['name']}"
        add_type = False
        if _connected['type'].lower() in _connected['name'].lower():
            t: str = _connected['type'].lower()
            n: str = _connected['name'].lower()
            for idx in set([n.find(t), n.rfind(t)]):
                _start = idx
                _end = _start + len(t)
                _prev = None if _start == 0 else _start - 1
                _next = None if _end + 1 >= len(n) else _end + 1
                if (_prev and n[_prev].isalpha()) or (_next and n[_next].isalpha()):
                    add_type = True
        else:
            add_type = True

        if add_type:
            data["connected device"] = f"{data['connected device']} ({_connected['type']})"

    return data


def get_clients(
    data: List[dict],
    verbose: bool = False,
    cache: callable = None,
    filters: List[str] = None,
    **kwargs
) -> list:
    """Remove all columns that are NA for all clients in the list"""
    data = utils.listify(data)

    data = [_client_concat_associated_dev(d, verbose=verbose, cache=cache, **kwargs) for d in data]
    if verbose:
        strip_keys = constants.CLIENT_STRIP_KEYS_VERBOSE
        if data and all([isinstance(d, dict) for d in data]):
            all_keys = set([k for d in data for k in d])
            data = [
                dict(
                    short_value(
                        k,
                        d.get(k),
                    )
                    for k in all_keys
                    if k not in strip_keys
                )
                for d in data
            ]
    else:
        _sort_keys = [
            "name",
            "macaddr",
            "vlan",
            "ip_address",
            "user_role",
            "network",
            "connection",
            "connected device",
            "gateway",
            "site",
            "group_name",
            "last_connection_time",
        ]
        if data and all([isinstance(d, dict) for d in data]):
            data = [
                dict(
                    short_value(
                        k,
                        f"wired ({data[idx].get('interface_port', '?')})" if d.get(k) == "NA" and k == "network" else d.get(k),
                    )
                    for k in _sort_keys
                )
                for idx, d in enumerate(data)
            ]

    if filters:
        _filter = "~|~".join(filters)
        data = [d for d in data if d["connected device"].lower() in _filter.lower()]
    # data = [_client_concat_associated_dev(d, verbose=verbose, cache=cache, **kwargs) for d in data]
    data = strip_no_value(data)

    return data


def strip_no_value(data: List[dict] | Dict[dict]) -> List[dict] | Dict[dict]:
    """strip out any columns that have no value in any row

    Accepts either List of dicts, or a Dict where the value for each key is a dict
    """
    no_val_strings = ["Unknown", "NA", "None", "--", ""]
    if isinstance(data, list):
        no_val: List[List[int]] = [
            [
                idx
                for idx, v in enumerate(id.values())
                if (not isinstance(v, bool) and not v) or (isinstance(v, str) and v and v in no_val_strings)
            ]
            for id in data
        ]
        if no_val:
            common_idx: set = set.intersection(*map(set, no_val))
            data = [{k: v for idx, (k, v) in enumerate(id.items()) if idx not in common_idx} for id in data]

    elif isinstance(data, dict) and all(isinstance(d, dict) for d in data.values()):
        no_val: List[List[int]] = [
            [
                idx
                for idx, v in enumerate(data[id].values())
                if (not isinstance(v, bool) and not v) or (isinstance(v, str) and v and v in no_val_strings)
            ]
            for id in data
        ]
        if no_val:
            common_idx: set = set.intersection(*map(set, no_val))
            data = {id: {k: v for idx, (k, v) in enumerate(data[id].items()) if idx not in common_idx} for id in data}
    else:
        log.error(
            f"cleaner.strip_no_value recieved unexpected type {type(data)}. Expects List[dict], or Dict[dict]. Data was returned as is."
        )

    return data


def sort_result_keys(data: List[dict], order: List[str] = None) -> List[dict]:
    # data = utils.listify(data)
    all_keys = list(set([ik for k in data for ik in k.keys()]))
    ip_word = "ipv4" if "ipv4" in all_keys else "ip_address"
    mask_word = "ipv4_mask" if "ipv4_mask" in all_keys else "subnet_mask"

    # concat ip_address & subnet_mask fields into single ip field ip/mask
    if ip_word in all_keys and mask_word in all_keys:
        for inner in data:
            if inner.get(ip_word) and inner.get(mask_word):
                mask = ipaddress.IPv4Network((inner[ip_word], inner[mask_word]), strict=False).prefixlen
                inner[ip_word] = f"{inner[ip_word]}/{mask}"
                del inner[mask_word]

    # calculate used memory percentage if ran with stats
    if "mem_total" and "mem_free" in all_keys:
        all_keys += ["mem_pct"]
        for inner in data:
            if inner.get("mem_total") is None or inner.get("mem_free") is None:
                continue
            if inner["mem_total"] and inner["mem_free"]:
                mem_pct = round(((inner["mem_total"] - inner["mem_free"]) / inner["mem_total"]) * 100, 2)
            elif inner["mem_total"] and inner["mem_total"] <= 100 and not inner["mem_free"]:  # CX send mem pct as mem total
                mem_pct = inner["mem_total"]
                inner["mem_total"], inner["mem_free"] = "--", "--"
            else:
                mem_pct = 0
            inner["mem_pct"] = f'{mem_pct}%'

    if order:
        to_front = order
    else:
        to_front = [
            "vlan_id",
            "name",
            "status",
            "type",
            "client_count",
            "model",
            'mode',
            "vlan_desc",
            "id",  # pvid for VLAN output
            "ip",
            "ip_address",
            "ipaddress",
            "ipv4",
            "subnet_mask",
            "ipv4_mask" "serial",
            "macaddr",
            "mac",
            "serial",
            "ap_deployment_mode",
            "group_name",
            "group",
            "site",
            "labels",
            "addr_mode",
            "admin_mode",
            "oper_mode",
            "untagged_ports",
            "tagged_ports",
            "is_management_vlan",
            "is_jumbo_enabled",
            "is_voice_enabled",
            "is_igmp_enabled",
            "uptime",
            'reboot_reason',
            'cpu_utilization',
            'mem_total',
            'mem_free',
            'mem_pct',
            'firmware_version',
            'version',
            'firmware_backup_version',
            'oper_state_reason',
        ]
    to_front = [i for i in to_front if i in all_keys]
    _ = [all_keys.insert(0, all_keys.pop(all_keys.index(tf))) for tf in to_front[::-1]]
    data = [{k: id.get(k) for k in all_keys} for id in data]

    return data


# TODO default verbose back to False once show device commands adapted to use --inventory so -v can be used for verbosity
def get_devices(data: Union[List[dict], dict], *, verbose: bool = True, cache: bool = False) -> Union[List[dict], dict]:
    """Clean device output from Central API (Monitoring)

    Args:
        data (Union[List[dict], dict]): Response data from Central API
        verbose (bool, optional): Not Used yet. Defaults to True.
        cache (bool, optional): If output is being cleaned for entry into cache. Defaults to False.

    Returns:
        Union[List[dict], dict]: The cleaned data with consistent field heading, and human readable values.
    """
    data = utils.listify(data)

    if not verbose:
        non_verbose_keys = [
                    "name",
                    "status",
                    "type",
                    "client_count",
                    "model",
                    "ip_address",
                    "macaddr",
                    "serial",
                    "group_name",
                    "site",
                    "labels",
                    "uptime",
                    "cpu_utilization",
                    "mem_total",
                    "mem_free",
                    "firmware_version",
        ]
        data = [{k: v for k, v in inner.items() if k in non_verbose_keys} for inner in data]

    # cache uses post cleaner keys
    # we don't actually use model or version for anything yet
    cache_keys = [
        "name",
        "status",
        "type",
        "model",
        "ip",
        "mac",
        "serial",
        "group",
        "site",
        "version"
    ]
    # gather all keys from all dicts in list each dict could potentially be a diff size
    # Also concats ip/mask if provided in sep fields
    data = sort_result_keys(data)

    # strip any cols that have no value across all rows
    data = strip_no_value(data)

    # send all key/value pairs through formatters and return
    data = _unlist(
        [
            dict(
                short_value(k, _check_inner_dict(v))
                for k, v in pre_clean(inner).items()
                if "id" not in k[-3:] and k != "mac_range"
            )
            for inner in data
        ]
    )

    data = utils.listify(data)

    if cache:
        data = [{k: v for k, v in d.items() if k in cache_keys} for d in data]

    data = sorted(data, key=lambda i: (i.get("site") or "", i.get("type") or "", i.get("name") or ""))

    return data


def get_audit_logs(data: List[dict], cache_update_func: callable = None) -> List[dict]:
    field_order = [
        "id",
        "ts",
        "app_name",
        "classification",
        "device_type",
        "description",
        "target",
        "ip_addr",
        "user",
        "has_details",
    ]
    data = [dict(short_value(k, d.get(k)) for k in field_order) for d in data]
    data = strip_no_value(data)

    if len(data) > 0 and cache_update_func:
        idx, cache_list = 1, []
        for d in data:
            if d.get("has details") is True:
                cache_list += [{"id": idx, "long_id": d["id"]}]
                d["id"] = idx
                idx += 1
            else:
                d["id"] = "-"
            del d["has details"]
        if cache_list:
            cache_update_func(cache_list)

    return data


def get_alerts(data: List[dict],) -> List[dict]:
    if isinstance(data, list) and "No Alerts" in data:
        return data

    field_order = [
        "timestamp",
        "severity",
        "type",
        # "group_name",
        # "device info",
        "description",
        # "labels",
        "acknowledged",
        # "acknowledged_by",
        # "acknowledged_timestamp",
        # "state",
    ]
    for d in data:
        # d["details"] = d.get("details") or {}
        # d["device info"] = f"{d['details'].get('hostname', '')}|" \
        #     f"{d.get('device_id', '')}|Group: {d.get('group_name', '')}".lstrip("|")
        d["severity"] = d.get("severity", "INFO")
        if d.get("acknowledged"):
            d["acknowledged"] = f'{"by " if d.get("acknowledged_by") else ""}' \
                f'{d.get("acknowledged_by")}{" @ " if d.get("acknowledged_by") else ""}' \
                f'{"" if not d.get("acknowledged_timestamp") else _log_timestamp(d["acknowledged_timestamp"])}'
        else:
            d["acknowledged"] = None

    data = [dict(short_value(k, d[k]) for k in field_order if k in d) for d in data]
    data = strip_no_value(data)

    return data


def get_event_logs(data: List[dict], cache_update_func: callable = None) -> List[dict]:
    # TODO accept verbose option and provide additional details with verbose. (currently just bypasses cleaner and displays yaml)

    field_order = [
        "id",
        "timestamp",
        # "level",
        # "event_type",
        "description",
        # "events_details",
        # "device_type",
        # "client_mac",
        "device info",
        # "device",
        # "hostname",
        # "device_serial",
        # "device_mac",
        # "group_name",
        # "labels",
        # "sites",
    ]
    for d in data:
        _dev_type = short_value('device_type', d.get('device_type', ''))
        if _dev_type:
            _dev_str = f"[{_dev_type[-1]}]" if _dev_type[-1] != "CLIENT" else ""
        d["device info"] = f"{_dev_str}{d.get('hostname', '')}|" \
            f"{d.get('device_serial', '')} Group: {d.get('group_name', '')}"
        # for key in ["device_type", "hostname", "device_serial", "device_mac"]:
        #     del d[key]

    # Stash event_details in cache indexed starting @ most recent event
    if len(data) > 1 and cache_update_func:
        idx, cache_list = 1, []
        for d in data:
            if d.get("has_rowdetail") is True:
                _details = {
                    k: v for inner in d["events_details"] for k, v in inner.items()
                }
                cache_list += [{"id": str(idx), "device": d["device info"], "details": _details}]
                d["id"] = idx
                idx += 1
            else:
                d["id"] = "-"
            # del d["has_rowdetail"]
        if cache_list:
            cache_update_func(cache_list)

    data = [dict(short_value(k, d[k]) for k in field_order if k in d) for d in data]
    data = strip_no_value(data)

    return data


def sites(data: Union[List[dict], dict]) -> Union[List[dict], dict]:
    data = utils.listify(data)

    _sorted = [
        "site_name",
        "site_id",
        "address",
        "city",
        "state",
        "zipcode",
        "country",
        "longitude",
        "latitude",
        "associated_device_count",
    ]  # , "tags"]
    key_map = {"associated_device_count": "associated devices", "site_id": "id", "site_name": "name"}

    return _unlist([{key_map.get(k, k): s[k] for k in _sorted} for s in data if s.get("site_name", "") != "visualrf_default"])


def get_certificates(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = utils.listify(data)
    short_keys = {
        "cert_name": "name",
        "cert_type": "type",
        "expire_date": "expiration",
        "expire": "expired",
        "cert_md5_checksum": "md5 checksum",
        "cert_sha1_checksum": "sha1 checksum",
    }

    if data and len(data[0]) != len(short_keys):
        log = logging.getLogger()
        log.error(
            f"get_certificates has returned more keys than expected, check for changes in response schema\n"
            f"    expected keys: {short_key.keys()}\n"
            f"    got keys: {data[0].keys()}"
        )
        return data
    else:
        data = [{short_keys[k]: d[k] if k != "expire_date" else _convert_datestring(d[k]) for k in short_keys} for d in data]
        return data


def get_lldp_neighbor(data: List[Dict[str, str]]) -> List[Dict[str, str]]:
    data = utils.listify(data)
    strip_keys = ["cid"]
    _short_val = {
        "1000BaseTFD - Four-pair Category 5 UTP, full duplex mode": "1000BaseT FD"
    }
    data = [{k: _short_val.get(d[k], d[k]) for k in d if d["localPort"] != "bond0" and k not in strip_keys} for d in data]

    return strip_no_value(utils.listify(data))


def get_vlans(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    short_keys = {
        # site
        "vlanName": "name",
        "vlanId": "pvid",
        # switch
        "id": "pvid",
        "ipaddress": "ip",
        "is_management_vlan": "mgmt",
        "is_igmp_enabled": "igmp",
        "is_jumbo_enabled": "jumbo",
        "is_voice_enabled": "voice",
        "tagged_ports": "tagged",
        "untagged_ports": "untagged",
        # gateways
        "admin_mode": "admin state",
        "ipv4": "ip",
        "ipv4_mask": "mask",
        "addr_mode": "type",
        "vlan_desc": "desc.",
        "vlan_id": "pvid",
    }

    data = sort_result_keys(data)
    # strip 'type' field which is 'primary vlan type' if all are "Regular"
    # ["Regular", "Private-Primary", "Private-Isolated", "Private-Community"]
    strip_keys = []
    if all([k.get("type", "") == "Regular" for k in data]):
        strip_keys += ["type"]

    data = [
        {short_keys.get(k, k.replace("_", " ")): _unlist(d[k]) for k in d if k not in strip_keys} for d in strip_no_value(data)
    ]

    return data


def routes(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    data = utils.unlistify(data)
    if isinstance(data, list) or "routes" not in data:
        return data
    else:
        rv: list = data["routes"]

    return [
        {"destination": f'{r["prefix"]}/{r["length"]}', "next hop": r["nexthop"]} for r in rv
    ]


def wids(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_keys = set([k for d in data for k in d])
    strip_keys = ["cust_id"]
    data = [
        dict(
            short_value(
                k,
                d.get(k),
            )
            for k in all_keys
            if k not in strip_keys
        )
        for d in data
    ]
    return data


def get_dhcp(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    data = _unlist(data)
    if "free_ip_addr_percent" in data[-1]:
        field_order = [
            "pool_name",
            "pool_size",
            "vlan_id",
            "subnet",
            "lease_time",
            "free_ip_addr_percent",
        ]
    else:
        field_order = [
            "client_name",
            "mac",
            "ip",
            "reservation",
            # "mask",
            "pool_name",
            "vlan_id",
            "subnet",
            "lease_start_ts",
            "lease_end_ts",
            "lease_time",
            "lease_time_left",
            # "infra_type",
            "client_type",
        ]

    data = [{"client name": None, **dict(short_value(k, d.get(k)) for k in field_order if k in d)} for d in data]
    data = strip_no_value(data)
    return data

def get_template_details_for_device(data: str) -> dict:
    """Convert form-data response to dict

    Args:
        data (str): string data with summary and optionally running config

    Returns:
        dict: dict with summary(dict), running config(str) and
        central side config(str).
    """
    import json

    summary, running_config, central_config = None, None, None
    split_line = data.split("\n")[0].rstrip()
    data_parts = [
        d.lstrip().splitlines() for d in data.split(split_line)
        if d.lstrip().startswith("Content-Disposition")
    ]
    for part in data_parts:
        if 'name="Summary"' in part[0]:
            summary = json.loads("\n".join(part[2:]))
            summary = {k.lower(): v for k, v in summary.items()}
        elif 'name="Device_running_config"' in part[0]:
            running_config = "\n".join(part[2:]).rstrip()
        elif 'name="Device_central_side_config"' in part[0]:
            central_config = "\n".join(part[2:]).rstrip()

    return {
        "summary": summary,
        "running_config": running_config,
        "central_config": central_config
    }

def parse_caas_response(data: Union[dict, List[dict]]) -> List[str]:
    """Parses Response Object from caas API updates output attribute

    """
    console = Console(emoji=False, record=True)
    data = utils.unlistify(data)
    out = []
    lines = f"[reset]{'-' * 22}"

    if data.get("_global_result", {}).get("status", '') == 0:
        global_res = "[bright_green]Success[/bright_green]"
    else:
        global_res = "[red]Failure[/red]"
    out += [lines, f"Global Result: {global_res}", lines]

    if data.get("cli_cmds_result"):
        out += ["\n -- [cyan bold]Command Results[/cyan bold] --"]
        for cmd_resp in data["cli_cmds_result"]:
            for _c, _r in cmd_resp.items():
                _r_code = _r.get("status")
                if _r_code == 0:
                    _r_pretty = "[bright_green]OK[/bright_green]"
                elif _r_code == 2:
                    _r_pretty = "[dark_orange3]WARNING[/dark_orange3]"
                else:
                    _r_pretty = "[red]ERROR[/red]" if _r_code == 1 else f"[red]ERROR ({_r_code})[/red]"

                out += [f" [{_r_pretty}] {_c}"]
                cmd_status = _r.get('status_str')
                if cmd_status:
                    _r_txt = f"[italic]{escape(cmd_status)}[/italic]"
                    out += [lines, _r_txt, lines]

        console.begin_capture()
        console.print("\n".join(out))
        out = console.end_capture()

    return out

def get_all_webhooks(data: List[dict]) -> List[dict]:
    class HookRetryPolicy(Enum):
        none = 0
        important = 1  # Up to 5 retries over 6 minutes
        critical = 2  # Up to 5 retries over 32 hours
        notfound = 99  # indicates an error retrieving policy from payload

    del_keys = ["retry_policy", "secure_token", "urls"]
    # flatten dict
    data = [
        {**{k: v for k, v in d.items() if k not in del_keys},
         "urls": "\n".join(d.get("urls", [])),
         "retry_policy": HookRetryPolicy(d.get("retry_policy", {}).get("policy", 99)).name,
         "token": d.get("secure_token", {}).get("token", ""), "token_created": d.get("secure_token", {}).get("ts", 0)
         }
         for d in data
    ]

    data = [
        dict(short_value(k, d[k]) for k in d) for d in strip_no_value(data)
    ]

    return data

def get_branch_health(data: list, down: bool = False, wan_down: bool = False) -> list:
    field_order = [
                "name",
                "potential_issue",
                "device_up",
                "device_down",
                "connected_count",
                "failed_count",
                "wan_tunnels_down",
                "wan_tunnels_no_issue",
                "wan_uplinks_down",
                "wan_uplinks_no_issue",
                "branch_cpu_high",
                "branch_device_status_up",
                "branch_device_status_down",
                "cape_state",
                "cape_state_dscr",
                "cape_url",
                "device_high_ch_2_4ghz",
                "device_high_ch_5ghz",
                "device_high_cpu",
                "device_high_mem",
                "device_high_noise_2_4ghz",
                "device_high_noise_5ghz",
                "insight_hi",
                "insight_lo",
                "insight_mi",
                "score",
                "silverpeak_state",
                "silverpeak_state_summary",
                "silverpeak_url",
                "user_conn_health_score",
                "wired_cpu_high",
                "wired_device_status_down",
                "wired_device_status_up",
                "wired_mem_high",
                "wlan_cpu_high",
                "wlan_device_status_down",
                "wlan_device_status_up",
                "branch_mem_high",
                "wlan_mem_high",
    ]
    # if wan_down:
    #     test = lambda d: d["wan_uplinks_down"] > 0 or d["wan_tunnels_down"] > 0
    # elif down:
    #     test = lambda d: d["device_down"] > 0
    # else:
    #     test = lambda d: True

    # data = [
    #     dict(short_value(k, d[k]) for k in field_order) for d in data if test(d)
    # ]
    data = [
        dict(short_value(k, d[k]) for k in field_order) for d in data
    ]
    data = strip_no_value(data)


    return data

def _inv_type(model: str, dev_type: str) -> DevTypes:
    if dev_type == "SWITCH":
        aos_sw_models = ["2530", "2540", "2920", "2930", "3810", "5400"]
        return "sw" if model[0:4] in aos_sw_models else "cx"

    return "gw" if dev_type == "GATEWAY" else dev_type.lower()


def get_device_inventory(data: List[dict], sub: bool = None) -> List[dict]:
    field_order = [
        "name",
        "status",
        # "device_type",
        "type",
        "model",
        "aruba_part_no",
        # "imei",
        "ip",
        "macaddr",
        "serial",
        "group",
        "site",
        "version",
        "services",
    ]
    # common_keys = set.intersection(*map(set, data))
    # combine type / device_type for verbose output, preferring type from cache

    data = [
        {"type": _inv_type(d["model"], d.get("type", d["device_type"])), **{key: val for key, val in d.items() if key != "device_type"}}
        for d in data
    ]
    data = [
        dict(short_value(k, d.get(k, "")) for k in field_order) for d in data
    ]
    data = sorted(strip_no_value(data), key=lambda i: (i["type"], i["model"]))

    if sub is not None:
        if sub:
            data = [{k: v for k, v in d.items()} for d in data if d["services"]]
        else:
            data = [{k: v for k, v in d.items()} for d in data if not d["services"]]

    return data


def get_client_roaming_history(data: List[dict]) -> List[dict]:
    # field order is b4 key conversion _short_key
    field_order = [
        "previous_ap_name",
        "ap_name",
        "ap_serial",
        "network",
        "bssid",
        "band",
        "channel",
        "roaming_type",
        "rssi",
        "ts",
    ]
    data = sorted(data, key=lambda i: i.get("ts", ""))
    data = [
        dict(short_value(k, d.get(k, "")) for k in field_order) for d in data
    ]
    data = strip_no_value(data)

    return data

def get_fw_version_list(data: List[dict], format: str = "rich") -> List[dict]:
    data = [
        dict(short_value(k, d[k]) for k in d) for d in data
    ]
    data = strip_no_value(data)
    if format != "rich" and data and "beta" in data[-1].keys():
        data = [
            {k: v.replace("\u2705", "True") for k, v in d.items()}
            for d in data
        ]

    return data

def get_subscriptions(data: List[dict],) -> List[dict]:
    field_order = [
        "license_type",
        "sku",
        "status",
        "subscription_type",
        "quantity",
        "subscription_key",
        "start_date",
        "end_date",
    ]
    return [
        dict(short_value(k, d[k]) for k in field_order) for d in data
    ]

def get_portals(data: List[dict],) -> List[dict]:
    field_order = [
        "name",
        "id",
        "auth_type",
        # "auth_type_num",
        "capture_url",
        # "is_aruba_cert",
        # "is_default",
        # "is_editable",
        # "is_shared",
        "register_accept_email",
        "register_accept_phone",
        # "scope"
    ]
    short_auth_types = {
        "Username/Password": "user/pass",
        "Self-Registration": "self-reg",
        "Anonymous": "anon",
    }
    for d in data:
        for k, v in short_auth_types.items():
            if k in d["auth_type"]:
                d["auth_type"] = d["auth_type"].replace(k, v)

    data = [
        dict(short_value(k, d.get(k, "")) for k in field_order) for d in data
    ]
    data = strip_no_value(data)

    return data

def get_ospf_neighbor(data: Union[List[dict], dict],) -> Union[List[dict], dict]:
    data = utils.listify(data)

    # send all key/value pairs through formatters and return
    # swapping "address" for ip here as address is also used for site address
    data = [
        dict(short_value(k if k != "address" else "ip", v) for k, v in inner.items()) for inner in data
    ]

    return data

def get_ospf_interface(data: Union[List[dict], dict],) -> Union[List[dict], dict]:
    data = utils.listify(data)

    # send all key/value pairs through formatters and return
    # swapping "address" for ip here as address is also used for site address
    data = [
        dict(
            short_value(
                k if k != "address" else "ip/mask", v if k != "address" else str(ipaddress.ip_network(f"{inner['address']}/{inner['mask']}", strict=False))
            ) for k, v in inner.items() if k != "mask"
        ) for inner in data
    ]

    return data

def show_interfaces(data: Union[List[dict], dict],) -> Union[List[dict], dict]:
    data = utils.listify(data)

    # TODO verbose and non-verbose
    # TODO verify oper_state and status are always the same and only show one of them
    # TODO determine if "mode" has any value, appears to always be Access on CX
    key_order = [
        "macaddr",
        "type",
        "phy_type",
        "port",
        "oper_state",
        "admin_state",
        "status",
        "intf_state_down_reason",
        "speed",
        "duplex_mode",
        "vlan",
        "allowed_vlan",
        "vlan_mode",
        "mode",
        "has_poe",
        "poe_state",
        "power_consumption",
        "is_uplink",
        "trusted",
        "tx_usage",
        "rx_usage",
        "mux",
        "vsx_enabled",
    ]
    strip_keys = ["port_number", "alignment",]

    # Append any additional keys to the end
    key_order = [*key_order, *data[-1].keys()]

    # send all key/value pairs through formatters and convert List[Dict] to Dict where port_number is key
    data = {
        d["port_number"] if not all(d.isdigit() for d in d["port_number"]) else int(d["port_number"]): dict(short_value(k, d.get(k),) for k in key_order if k not in strip_keys) for d in data
    }

    return strip_no_value(data)

def show_ts_commands(data: Union[List[dict], dict],) -> Union[List[dict], dict]:
    key_order = [
        "command_id",
        "category",
        "command",
    ]
    strip_keys = [
        "summary"
    ]
    # data = simple_kv_formatter(data)
    data = [
        dict(short_value(k, d.get(k),) for k in key_order if k not in strip_keys) for d in data if "arguments" not in d.keys()
    ]

    return data

def get_overlay_routes(data: Union[List[dict], dict], format: str = "rich", simplify: bool = True) -> Union[List[dict], dict]:
    if "routes" in data:
        data = data["routes"]

    data = utils.listify(data)
    if "nexthop_list" in data[-1].keys():
        base_data = [{"destination": f'{r["prefix"]}/{r["length"]}', **{k: v for k, v in r.items() if k not in ["prefix", "length", "nexthop_list"]}} for r in data]
        outdata = base_data
    else:
        base_data = [{"destination": f'{r["prefix"]}/{r["length"]}', **{k: v for k, v in r.items() if k not in ["prefix", "length", "nexthop"]}} for r in data]
        if isinstance(data[-1]["nexthop"], list):
            next_hop_data = [[{"interface": "" if not hops.get("interface") else utils.unlistify(hops["interface"]), **{k if k != "address" else "nexthop": v for k, v in hops.items() if k != "interface"}} for hops in r["nexthop"]] for r in data]
        else:
            next_hop_data = [[{"nexthop": _get_dev_name_from_mac(r["nexthop"], dev_type=("gw", "ap",), summary_text=True)}] for r in data]

        field_order = [
            "destination",
            "interface",
            "nexthop",
            "protocol",
            "flags",
            "learn_time",
            "metric",
            "is_best",
        ]

        # Collapse next_hop data into base dict
        outdata = []
        for base, nh in zip(base_data, next_hop_data):
            for idx, route in enumerate(nh):
                if idx == 0 or not simplify:
                    route = {**base, **route}
                else:
                    route = {**{k: "" for k in base.keys()}, **route}
                # outdata += [route]  # Put fields in desired order
                outdata += [{k: route.get(k) for k in field_order if k in route.keys()}]  # Put fields in desired order

        if format == "rich" and data and "is_best" in outdata[-1].keys():
            outdata = [
                {k: str(v).replace("True", "\u2705").replace("False", "") if k == "is_best" else v for k, v in d.items()}
                for d in outdata
            ]

    _short_value["0.0.0.0"] = "0.0.0.0"  # OVERRIDE default
    data = simple_kv_formatter(outdata)
    # data = simple_kv_formatter(
    #     [
    #         {
    #             **{k: v for k, v in r.items() if k != "nexthop"},
    #             "nexthop": [{k: v if k != "interface" else utils.unlistify(v) for k, v in hops.items()} for hops in r["nexthop"]]
    #         } for r in data
    #     ]
    # )

    return data


def get_overlay_interfaces(data: Union[List[dict], dict]) -> Union[List[dict], dict]:
    try:
        data = [
            {
                k: v if k != "endpoint" else _get_dev_name_from_mac(v, dev_type="ap") for k, v in i.items()
            }
            for i in data
        ]
    except Exception as e:
        log.error(f'get_overlay_interfaces cleaner threw {e.__class__.__name__} trying to get apo name from mac, skipping.', show=True)

    return simple_kv_formatter(data)

def get_full_wlan_list(data: List[dict] | str | Dict, verbosity: int = 0) -> List[dict]:
    if isinstance(data, list) and data and isinstance(data[0], str):
        data = json.loads(data[0])
    if isinstance(data, dict) and "wlans" in data:
        data = data["wlans"]

    verbosity_keys = [
        [
            'group',
            'name',
            'essid',
            'type',
            'hide_ssid',
            'disable_ssid',
            'rf_band',
            'mac_authentication',
            'vlan',
            'opmode',
            'access_type'
        ]
    ]
    pretty_data = []
    for wlan in data:
        ssid_data = {k: v for k, v in wlan.items() if k in verbosity_keys[verbosity]}
        if ssid_data.get("name", "") == ssid_data.get("essid", ""):
            ssid_data["name"] = None
        pretty_data += [ssid_data]

    pretty_data = simple_kv_formatter(pretty_data)
    pretty_data = strip_no_value(pretty_data)
    return pretty_data

    # "visitor name": "barn-bench-outlet-old",
    # "username": "E8-DB-84-D3-11-4D",
    # "sponsor name": "wade",
    # "role name": "[Employee]",
    # "start time": "Sep 24, 2020 2:21:49 PM",
    # "create time": "Sep 24, 2020 2:21:49 PM",
    # "expire time": 0,
    # "id": "3103",
    # "sponsor profile": "1",
    # "enabled": true,
    # "current state": "active",
    # "notes": "Shelly 2.5 ~ soldering iron, magnifying light\nChip Info:\n - Chip Family: ESP8266\n - Chip Model: ESP8266EX\n - Chip ID: 00D3114D\n - MAC Address: E8:DB:84:D3:11:4D\n\nOld Fried Shelly 2.5: 68-C6-3A-F9-DF-58",
    # "role id": 3,
    # "mac": "E8-DB-84-D3-11-4D",
    # "mac auth": true,
    # "source": "mac_create",
    # "do expire": "0",
    # "no portal": "1",
    # "mpsk enable": "1",
    # "no password": "1",
    # "remote addr": "10.0.110.247",
    # "airgroup enable": "",
    # "airgroup shared": "",
    # "expire postlogin": "0",
    # "simultaneous use": "5",
    # "airgroup shared role": "",
    # "airgroup shared time": "",
    # "airgroup shared user": "",
    # "smtp auto send field": "mpsk_refresh",
    # "sponsor profile name": "Super Administrator",
    # "airgroup shared group": "",
    # "airgroup shared location": ""

def get_device(data: List[dict], verbose_level: int = 0, cloud_auth: bool = False,) ->  List[dict]:
    verbose_fields = {
        0: [
            "visitor_name",
            "username",
            "mac",
            "sponsor_name",
            "role_name",
            "start_time",
            "create_time",
            "expire_time",
            "enabled",
            "current_state",
            "source",
            "remote_addr"
        ]
    }
    cloud_auth_keys = {
        "mac": "Mac Address",
        "visitor_name": "Client Name"
    }

    if cloud_auth:
        return [{cloud_auth_keys[k]: inner[k] for k in cloud_auth_keys if k in inner} for inner in data]

    # data = [{**{k: inner[k] for k in field_order if k in inner}, **{k: v for k, v in inner.items() if k in verbose_fields[verbose_level] and not k.startswith("_")}} for inner in data]
    data = [{k: inner[k] for k in verbose_fields[verbose_level] if k in inner} for inner in data]
    return simple_kv_formatter(data)


