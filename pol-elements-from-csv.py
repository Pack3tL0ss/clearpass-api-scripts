#!/usr/bin/env python3
#
# Author: Wade Wells github/Pack3tL0ss
#
# Version: 2020-1.0
#

from pathlib import Path
import sys
from typing import Union
import requests
import csv
import xml.etree.ElementTree as ET

from common import cppmauth, log
cppm_config = cppmauth.config.get("CPPM", {})

BASE_DIR = Path(__file__).parent

CPPM_ARGS = (cppmauth.clearpass_fqdn, cppmauth.token_type, cppmauth.access_token)
HEADERS = {'Content-Type': 'application/json', "Authorization": f"{cppmauth.token_type} {cppmauth.access_token}"}
BASE_URL = f"https://{cppmauth.clearpass_fqdn}/api"

# -- // Variables Pulled from config.yaml \\ --
AUTHZ_SRC = cppm_config.get("authz_src")
ROLE_NAME_PFX = cppm_config.get("role_name_pfx")
ENF_PROFILE_PFX = cppm_config.get("enf_profile_pfx")
ROLE_MAPPING_NAME = cppm_config.get("role_mapping_name")
ROLE_MAPPING_DESCRIPTION = cppm_config.get("role_mapping_description")
ENF_POLICY_NAME = cppm_config.get("enf_policy_name")
ENF_POLICY_DESCRIPTION = cppm_config.get("enf_policy_description")


def load_import(import_file: str) -> list:
    """Load csv import file.

    Expects csv with no header where first col is AD DN/Path and second col is role
    AD DN/Path will be stripped to the text following the last '/'

    rows with no data in the second col are skipped.

    Args:
        import_file (str): path of import file

    Returns:
        list: list of tuples (AD Group, role to assign)
    """
    with open(import_file, newline='') as csvfile:
        dialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        lines = csv.reader(csvfile, dialect)
        ad2vpn_map = [(Path(row[0]).name, row[1]) for row in lines if row[1] and " " not in row[1]]

    return ad2vpn_map


def post_role(role_dict: Union[dict, list]) -> list:
    """Create new role in CPPM via Rest API

    Args:
        role_dict (Union[dict, list]): A single dict or a list of dicts where each dict
            must contain 'name' and can optionally contain 'description' for each role to
            be created.


    Returns:
        list: list of dicts containing name and id for each role created.  False is inserted
              into list for any failures.
    """
    url = f"{BASE_URL}/role"

    role_dict_list = [role_dict] if not isinstance(role_dict, list) else role_dict

    _res = []
    for role in role_dict_list:
        try:
            r = requests.post(url, json=role, headers=HEADERS)
            if r.ok:
                log.info(f"POST[/api/role]:{role.get('name')}:OK:{r.status_code}:{r.reason}")
                _res += [{k: v for k, v in r.json().items() if k in ["id", "name"]}]
            else:
                _msg = "\n".join([f"\t{k}: {v}" for k, v in r.json().items() if v])
                log.error(f"POST:{role.get('name')}:{url}\n{_msg}")
                _res += [False]
        except Exception as e:
            _msg = "Exception: {}\n{}".format(e, "\n".join([f"\t{k}: {v}" for k, v in e.__dict__.items()]))
            log.exception(_msg)
            _res += [False]

    return _res


def build_role_map_dict(mapping_list: list) -> dict:
    """Builds Dictionary used as payload for API post to implement role mapping based on import data.

    Args:
        mapping_list (list): list of tuples, (AD Group, Role To assign)

    Returns:
        dict: Role Mapping Dict
    """
    role_map_dict = {
        "name": ROLE_MAPPING_NAME,
        "description": ROLE_MAPPING_DESCRIPTION,
        "default_role_name": "[Other]",
        "rule_combine_algo": "evaluate-all",
        "rules": []
    }

    for m in mapping_list:
        if len(m) != 2:
            raise(ValueError(f"Unexpected mapping length ({m}), should be a tuple (ad group, role(vpn))"))

        role_map_dict["rules"] += [
            {
                "match_type": "and",
                "role_name": m[1],
                "condition": [
                    {
                        "type": f"Authorization:{AUTHZ_SRC}",
                        "name": "memberOf",
                        "oper": "CONTAINS",
                        "value": m[0],
                        "value_disp_name": m[0]
                    },
                    {
                        "type": "Radius:Cisco-ASA",
                        "name": "ASA-TunnelGroupName",
                        "oper": "CONTAINS",
                        "value": m[1],
                        "value_disp_name": m[1]
                    }
                ]
            },
        ]

    return role_map_dict


def get_roles() -> list:
    """Get Existing Roles and associated role ids from CPPM.

    Returns:
        list: list of dicts with name and id for each role that exists
    """
    url = f"{BASE_URL}/role"
    url_params = {
        "offset": 0,
        "limit": 25
    }

    def _parse_response(response: requests.Response, roles: list = None) -> tuple:
        _roles = roles or []
        _json = response.json()
        _items = _json.get("_embedded", {}).get("items")
        _next_url = _json.get("_links", {}).get("next", {}).get('href')
        if _items:
            _roles += [{k: v for k, v in i.items() if k in ["id", "name"]} for i in _items]

        return (_next_url, _roles)

    _roles = []
    try:
        r = requests.get(url, params=url_params, headers=HEADERS)
        if r.ok:
            _next_url, _roles = _parse_response(r)

            while _next_url:
                r = requests.get(_next_url, headers=HEADERS)
                if r.ok:
                    _next_url, _roles = _parse_response(r, roles=_roles)

    except Exception as e:
        _msg = "Exception: \n{}".format("\n".join([f"\t{k}: {v}" for k, v in e.__dict__.items()]))
        log.exception(_msg)

    return _roles


def get_cppm_version() -> dict:
    """Get CPPM version via restful API

    Used by xml builder

    Returns:
        dict: version
    """
    url = f"{BASE_URL}/cppm-version"

    cppm_version = "error"
    try:
        r = requests.get(url, headers=HEADERS)
        if r.ok:
            cppm_version = f"6.{r.json().get('app_minor_version')}"
        else:
            _msg = "\n".join([f"\t{k}: {v}" for k, v in r.json().items() if v])
            log.error(f"POST:ERROR:{url}\n{_msg}")

    except Exception as e:
        _msg = "Exception: \n{}".format("\n".join([f"\t{k}: {v}" for k, v in e.__dict__.items()]))
        log.exception(_msg)

    return {"version": cppm_version}


def post_role_mapping(role_dict: dict) -> list:
    """Post role mapping to ClearPass"""

    url = f"{BASE_URL}/role-mapping"

    # prepend pfx to all role names
    _role_dict = role_dict.copy()
    for r in _role_dict.get("rules", {}):
        r["role_name"] = f"{ROLE_NAME_PFX}{r['role_name']}"

    try:
        r = requests.post(url, json=_role_dict, headers=HEADERS)
        if r.ok:
            log.info(f"POST:OK:{url}:{r.status_code}:{r.reason}")
        else:
            _msg = "\n".join([f"\t{k}: {v}" for k, v in r.json().items() if v])
            log.error(f"POST:ERROR:{url}\n{_msg}")
    except Exception as e:
        _msg = "Exception: {}\n{}".format(e, "\n".join([f"\t{k}: {v}" for k, v in e.__dict__.items()]))
        log.exception(_msg)


def delete_roles(role_list: list):
    """Delete roles from ClearPass previously added with this script

    This function only runs if the section that calls it is uncommented, just a clean-up function.
    The role_list is created by comparing the input file to the roles that exist on ClearPass.

    Args:
        role_list (list): list of unique role names to delete
    """
    base_url = f"{BASE_URL}/role/name/"
    for role in role_list:
        try:
            r = requests.delete(base_url + role, headers=HEADERS)
            if r.ok:
                log.info(f"DEL:OK:[/api/role/name/{role}]:{r.status_code}:{r.reason}")
            else:
                _msg = "\n".join([f"\t{k}: {v}" for k, v in r.json().items() if v])
                log.error(f"DEL:ERROR:[/api/role/name/{role}]{r.status_code}:{r.reason}\n{_msg}")
        except Exception as e:
            _msg = "DEL:Exception:[/api/role/name/{}]: {}\n{}".format(
                role, e, "\n".join([f"\t{k}: {v}" for k, v in e.__dict__.items()]))
            log.exception(_msg)


# -- // XML IMPORT FILE BUILDERS \\ --
def build_enforcement_profile_xml(mapping_list):
    root = ET.Element("TipsContents", {"xmlns": "http://www.avendasys.com/tipsapiDefs/1.0"})
    ET.SubElement(root, "TipsHeader", get_cppm_version())
    enf_profiles = ET.SubElement(root, "RadiusEnfProfiles")

    for m in mapping_list:
        enf_profile_dict = {
            "description": f"{ENF_PROFILE_PFX}{m[1]}",
            "name": f"{ENF_PROFILE_PFX}{m[1]}",
            "action": "Accept"
        }
        enf_attr_dict = {
            "displayValue": m[1],
            "value": m[1],
            "name": "ASA-TunnelGroupName",
            "type": "Radius:Cisco-ASA"
        }
        enf_profile = ET.SubElement(enf_profiles, "RadiusEnfProfile", enf_profile_dict)
        attr_list = ET.SubElement(enf_profile, "AttributeList")
        ET.SubElement(attr_list, "Attribute", enf_attr_dict)

    #  Write out results for ClearPass
    tree = ET.ElementTree(root)
    tree.write(BASE_DIR.joinpath("out", "enforcement-profile.xml"))


def build_role_map_xml(mapping_list):
    root = ET.Element("TipsContents", {"xmlns": "http://www.avendasys.com/tipsapiDefs/1.0"})
    ET.SubElement(root, "TipsHeader", get_cppm_version())
    role = ET.SubElement(root, "Roles")
    role_mappings = ET.SubElement(root, "RoleMappings")

    role_mapping_dict = {
        "description": ROLE_MAPPING_DESCRIPTION,
        "name": ROLE_MAPPING_NAME,
        "ruleCombineAlgo": "evaluate-all",
        "dftRoleName": "[Other]"
    }

    role_mapping = ET.SubElement(role_mappings, "RoleMapping", role_mapping_dict)
    pol = ET.SubElement(role_mapping, "Policy", {"ruleCombiningAlgorithm": "evaluate-all"})
    rule_list = ET.SubElement(pol, "RuleList")

    for m in mapping_list:
        role_dict = {
            "description": f"User is Authorized to use {m[1]} Tunnel",
            "name": f"{ROLE_NAME_PFX}{m[1]}"
        }
        ET.SubElement(role, "Role", role_dict)
        rule = ET.SubElement(rule_list, "Rule")
        condition = ET.SubElement(rule, "Condition")
        expr = ET.SubElement(condition, "Expression", {"displayOperator": "MATCHES_ALL", "operator": "and"})
        attr_list = ET.SubElement(expr, "AttributeList")

        ad_grp_match_dict = {
            "displayValue": m[0],
            "value": m[0],
            "operator": "CONTAINS",
            "name": "memberOf",
            "type": f"Authorization:{AUTHZ_SRC}"
        }

        tunnel_match_dict = {
            "displayValue": m[1],
            "value": "",
            "operator": "CONTAINS",
            "name": "ASA-TunnelGroupName",
            "type": "Radius:Cisco-ASA"
        }
        ET.SubElement(attr_list, "RuleAttribute", ad_grp_match_dict)
        ET.SubElement(attr_list, "RuleAttribute", tunnel_match_dict)

        result_dict = {
            "displayValue": f"{ROLE_NAME_PFX}{m[1]}",
            # "value": str(existing_roles.get(m[1], "ERROR")),
            "value": "",
            "name": "Role",
            "type": "Tips"
        }
        result_list = ET.SubElement(rule, "ResultList")
        ET.SubElement(result_list, "RuleResult", result_dict)

    #  Write out results for ClearPass
    tree = ET.ElementTree(root)
    tree.write(BASE_DIR.joinpath("out", "role-mapping.xml"))


def build_enforcement_policy_xml(mapping_list):
    user_authenticated_rule = {
        "displayValue": "[User Authenticated]",
        "value": "[User Authenticated]",
        "operator": "EQUALS",
        "name": "Role",
        "type": "Tips"
    }
    root = ET.Element("TipsContents", {"xmlns": "http://www.avendasys.com/tipsapiDefs/1.0"})
    ET.SubElement(root, "TipsHeader", get_cppm_version())
    enf_policies = ET.SubElement(root, "EnforcementPolicies")
    enf_policy_dict = {
        "description": ENF_POLICY_DESCRIPTION,
        "name": ENF_POLICY_NAME,
        "policyType": "RADIUS",
        "defaultProfileName": "[Deny Access Profile]"
    }

    enf_policy = ET.SubElement(enf_policies, "EnforcementPolicy", enf_policy_dict)
    pol = ET.SubElement(enf_policy, "Policy", {"ruleCombiningAlgorithm": "first-applicable"})
    rule_list = ET.SubElement(pol, "RuleList")

    for m in mapping_list:
        rule = ET.SubElement(rule_list, "Rule")
        condition = ET.SubElement(rule, "Condition")
        expr = ET.SubElement(condition, "Expression", {"displayOperator": "MATCHES_ALL", "operator": "and"})
        attr_list = ET.SubElement(expr, "AttributeList")

        role_attr_dict = {
            "displayValue": f"{ROLE_NAME_PFX}{m[1]}",
            "value": "",
            "operator": "EQUALS",
            "name": "Role",
            "type": "Tips"
        }
        ET.SubElement(attr_list, "RuleAttribute", role_attr_dict)
        ET.SubElement(attr_list, "RuleAttribute", user_authenticated_rule)

        result_dict = {
            "displayValue": "[Allow Access Profile]",
            "value": "1",
            "name": "Enforcement-Profile",
            "type": "Tips"
        }
        result_list = ET.SubElement(rule, "ResultList")
        ET.SubElement(result_list, "RuleResult", result_dict)

    #  Write out results for ClearPass
    tree = ET.ElementTree(root)
    tree.write(BASE_DIR.joinpath("out", "enforcement-policy.xml"))


def verify_input_file():
    if len(sys.argv) > 1:
        in_file = Path(sys.argv[1])
    else:
        in_file = cppm_config.get("in_file")
        if in_file:
            in_file = Path(in_file)
            log.info(f"Using {in_file} found in config")
        else:
            print("Missing single argument <Name of import file (csv format)> or 'in_file' defined in config.yaml")
            return

    # allow user to specify filename without specifying the "in" dir
    if in_file.exists and in_file.parent.name != "in":
        in_file = in_file.parent.joinpath("in", in_file.name)

    if not in_file.exists():
        log.error(f"{in_file.name} Not Found")
        return
    elif not in_file.stat().st_size > 0:
        log.error(f"{in_file} Found but appears to be empty")
        return
    else:
        return in_file


if __name__ == "__main__":
    in_file = verify_input_file()
    if in_file:
        ad2vpn_map = load_import(in_file)
        # noqa E116
        # existing_roles = get_roles()
        # role_dict = build_role_map_dict(ad2vpn_map)

        # Uncomment to clean out roles from previous runs
        # _temp = sorted([e["name"] for e in existing_roles if e["name"] in [r["role_name"] for r in role_dict.get("rules")]])
        # delete_roles(_temp)

        # if role_dict.get("rules"):
        #     referenced_roles = [f"{ROLE_NAME_PFX}{r.get('role_name')}" for r in role_dict.get("rules")]
        #     new_roles = [{"name": r} for r in set(referenced_roles) if r not in [e.get('name') for e in existing_roles]]
            # NoQA
            # if new_roles:
            #     log.info("Creating New Roles Referenced in Role Mapping Not currently in CPPM")
            #     res = post_role(new_roles)
            #     if res and False not in res:
            #         print(f"{len(res)} Roles Created.")
            #         existing_roles = [*existing_roles, *res]
            #     else:
            #         print("Error returned while adding new roles")

            # post_role_mapping(role_dict)

        # role_id_by_name = {i["name"]: i["id"] for i in existing_roles}
        log.info("Creating Import Files")
        build_role_map_xml(ad2vpn_map)
        build_enforcement_profile_xml(ad2vpn_map)
        build_enforcement_policy_xml(ad2vpn_map)

    print("Script Complete")
