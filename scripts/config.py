import argparse
from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re
import sys

import yaml

from scripts.model import ConversionError

DEFAULT = {"protocol": "both", "chain": {"enabled": False, "dialer_proxy": ""},
           "countries": [], "max_nodes": 100, "sort_by": "score"}


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, (str, int, bool)) or key in result:
            raise ConversionError("duplicate or invalid YAML key")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def merge(base: dict, extra: dict) -> dict:
    result = deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


@dataclass
class Profile:
    name: str
    settings: dict

    @property
    def protocols(self):
        protocol = self.settings["protocol"]
        return {"tcp", "udp"} if protocol == "both" else {protocol}


def validate_profile(name: str, settings: dict) -> Profile:
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
        raise ConversionError("invalid profile name")
    if set(settings) - set(DEFAULT):
        raise ConversionError("unknown profile setting")
    if settings["protocol"] not in {"tcp", "udp", "both"}:
        raise ConversionError("invalid profile protocol")
    chain = settings["chain"]
    if not isinstance(chain, dict) or set(chain) - {"enabled", "dialer_proxy"}:
        raise ConversionError("invalid chain settings")
    if not isinstance(chain.get("enabled"), bool) or not isinstance(chain.get("dialer_proxy"), str):
        raise ConversionError("invalid chain parameter types")
    group = chain["dialer_proxy"]
    if any(ord(char) < 32 for char in group) or len(group) > 200:
        raise ConversionError("invalid dialer proxy name")
    if chain["enabled"] and not group.strip():
        raise ConversionError("chain is enabled but dialer_proxy is empty")
    countries = settings["countries"]
    if not isinstance(countries, list) or not all(isinstance(c, str) and re.fullmatch(r"[A-Z]{2}", c) for c in countries):
        raise ConversionError("countries must be a list of uppercase two-letter codes")
    if type(settings["max_nodes"]) is not int or not 0 <= settings["max_nodes"] <= 10000:
        raise ConversionError("max_nodes must be an integer from 0 to 10000")
    if settings["sort_by"] not in {"score", "speed", "country"}:
        raise ConversionError("invalid sort order")
    return Profile(name, settings)


def arguments(argv=None, environ=None):
    env = os.environ if environ is None else environ
    cli = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description="Convert official VPN Gate OpenVPN profiles to Mihomo providers")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--profile", default=env.get("INPUT_PROFILE") or None)
    parser.add_argument("--protocol", choices=["inherit", "tcp", "udp", "both"], default=env.get("INPUT_PROTOCOL") or "inherit")
    chain = parser.add_mutually_exclusive_group()
    chain.add_argument("--chain", choices=["inherit", "on", "off"], default=None)
    chain.add_argument("--no-chain", action="store_true")
    parser.add_argument("--dialer-proxy", default=env.get("INPUT_DIALER_PROXY") or None)
    parser.add_argument("--countries", default=env.get("INPUT_COUNTRIES") or None,
                        help="Comma-separated country codes; '*' explicitly removes the country filter")
    parser.add_argument("--max-nodes", default=env.get("INPUT_MAX_NODES") or None)
    parser.add_argument("--sort-by", choices=["inherit", "score", "speed", "country"], default=env.get("INPUT_SORT_BY") or "inherit")
    args = parser.parse_args(cli)
    if args.no_chain:
        args.chain = "off"
    elif args.chain is None:
        args.chain = env.get("INPUT_CHAIN") or "inherit"
        # A CLI dialer name is shorthand for enabling chaining; the Actions
        # form has an independent explicit on/off/inherit control.
        if any(value == "--dialer-proxy" or value.startswith("--dialer-proxy=") for value in cli) and not env.get("INPUT_CHAIN"):
            args.chain = "on"
    return args


def resolve(args) -> tuple[list[Profile], dict]:
    try:
        text = args.config.read_text(encoding="utf-8-sig")
        if len(text) > 65536:
            raise ConversionError("config file exceeds size limit")
        config = yaml.load(text, Loader=UniqueLoader)
    except (OSError, yaml.YAMLError):
        raise ConversionError("cannot read config YAML") from None
    if not isinstance(config, dict) or config.get("version") != 1:
        raise ConversionError("config version must be 1")
    if set(config) - {"version", "defaults", "profiles", "fetch"}:
        raise ConversionError("unknown top-level config key")
    if not isinstance(config.get("defaults", {}), dict):
        raise ConversionError("defaults must be a mapping")
    default = merge(DEFAULT, config.get("defaults", {}))
    validate_profile("defaults", default)
    profiles = config.get("profiles", {"all": {}})
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= 32:
        raise ConversionError("profiles must contain 1 to 32 named mappings")
    resolved = {}
    for name, values in profiles.items():
        if not isinstance(values, dict):
            raise ConversionError("profile settings must be mappings")
        resolved[name] = validate_profile(name, merge(default, values))
    overrides = {}
    if args.protocol != "inherit":
        overrides["protocol"] = args.protocol
    if args.chain not in {"inherit", "on", "off"}:
        raise ConversionError("invalid chain override")
    if args.chain != "inherit":
        overrides["chain"] = {"enabled": args.chain == "on"}
    if args.dialer_proxy is not None:
        overrides.setdefault("chain", {})["dialer_proxy"] = args.dialer_proxy
    if args.countries is not None:
        overrides["countries"] = [] if args.countries == "*" else [c.strip().upper() for c in args.countries.split(",")]
    if args.max_nodes is not None:
        try:
            overrides["max_nodes"] = int(args.max_nodes)
        except ValueError:
            raise ConversionError("invalid max_nodes override") from None
    if args.sort_by != "inherit":
        overrides["sort_by"] = args.sort_by
    if args.profile:
        if args.profile not in resolved:
            raise ConversionError("selected profile does not exist")
        selected = [validate_profile(args.profile, merge(resolved[args.profile].settings, overrides))]
    elif overrides:
        values = merge(default, overrides)
        name = {"tcp": "tcp", "udp": "udp", "both": "all"}.get(values["protocol"], "invalid")
        if values["chain"]["enabled"]:
            name += "-chain"
        selected = [validate_profile(name, values)]
    else:
        selected = list(resolved.values())
    if not isinstance(config.get("fetch", {}), dict):
        raise ConversionError("fetch settings must be a mapping")
    fetch = merge({"timeout_seconds": 30, "retries": 3, "concurrency": 4}, config.get("fetch", {}))
    if set(fetch) != {"timeout_seconds", "retries", "concurrency"}:
        raise ConversionError("unknown fetch setting")
    for key, maximum in (("timeout_seconds", 120), ("retries", 5), ("concurrency", 8)):
        if type(fetch[key]) is not int or not 1 <= fetch[key] <= maximum:
            raise ConversionError("invalid fetch limits")
    return selected, fetch
