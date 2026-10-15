from copy import deepcopy
import hashlib
import json
import re

import yaml

from scripts.model import Candidate, ConversionError


class ProviderDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def represent_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


ProviderDumper.add_representer(str, represent_string)


def node_name(candidate: Candidate) -> str:
    proxy = candidate.proxy
    server = re.sub(r"[^a-zA-Z0-9.-]", "-", proxy["server"])
    return f"VPNGate-{candidate.source.country}-{server}-{proxy['port']}-{proxy['proto'].upper()}"


def build_provider(profile, candidates: list[Candidate]) -> tuple[str, dict]:
    settings = profile.settings
    countries = set(settings["countries"])
    filtered = [c for c in candidates if c.proxy["proto"] in profile.protocols
                and (not countries or c.source.country in countries)]
    primary = settings["sort_by"]
    def order(c):
        fingerprint = hashlib.sha256(json.dumps(c.proxy, sort_keys=True).encode()).hexdigest()
        stable = (c.source.country, c.proxy["server"], c.proxy["port"], c.proxy["proto"], fingerprint)
        if primary == "country":
            return (c.source.country, -c.source.score, -c.source.speed, *stable)
        return (-(c.source.score if primary == "score" else c.source.speed), *stable)
    unique = {}
    for candidate in sorted(filtered, key=order):
        unique.setdefault(candidate.endpoint, candidate)
    selected = list(unique.values())
    available = {c.proxy["proto"] for c in selected}
    if not profile.protocols.issubset(available):
        missing = ",".join(sorted(profile.protocols - available))
        raise ConversionError(f"profile {profile.name} has no compatible {missing} nodes after filtering")
    maximum = settings["max_nodes"]
    if maximum and maximum < len(profile.protocols):
        raise ConversionError("max_nodes is too small to retain every requested protocol")
    if maximum and len(selected) > maximum:
        # Keep at least one node for every explicitly requested transport.
        kept = selected[:maximum]
        for proto in sorted(profile.protocols - {c.proxy["proto"] for c in kept}):
            replacement = next(c for c in selected if c.proxy["proto"] == proto)
            counts = {p: sum(c.proxy["proto"] == p for c in kept) for p in profile.protocols}
            index = next(i for i in range(len(kept) - 1, -1, -1) if counts[kept[i].proxy["proto"]] > 1)
            kept[index] = replacement
        selected = sorted(kept, key=order)
    proxies = []
    for candidate in selected:
        proxy = {"name": node_name(candidate), **deepcopy(candidate.proxy)}
        if settings["chain"]["enabled"]:
            group = settings["chain"]["dialer_proxy"]
            if group == proxy["name"]:
                raise ConversionError("dialer proxy refers to the exported node itself")
            proxy["dialer-proxy"] = group
        proxies.append(proxy)
    names = {p["name"] for p in proxies}
    if settings["chain"]["enabled"] and settings["chain"]["dialer_proxy"] in names:
        raise ConversionError("dialer proxy must reference an external node/group")
    output = yaml.dump({"proxies": proxies}, Dumper=ProviderDumper, allow_unicode=True,
                       sort_keys=False, width=120)
    # Round-trip the actual serialized document before allowing publication.
    if yaml.safe_load(output) != {"proxies": proxies}:
        raise ConversionError("provider YAML round-trip failed")
    fingerprints = {p["name"]: hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest() for p in proxies}
    info = {"node_count": len(proxies), "protocols": sorted({p["proto"] for p in proxies}),
            "chain_enabled": settings["chain"]["enabled"], "countries": sorted({c.source.country for c in selected}),
            "sha256": hashlib.sha256(output.encode()).hexdigest(), "node_fingerprints": fingerprints}
    return output, info
