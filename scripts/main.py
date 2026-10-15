"""CLI entry point; source failures cannot replace an existing output snapshot."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.config import arguments, resolve
from scripts.fetch import API_URL, HttpClient, parse_csv, supplement
from scripts.mihomo import build_provider
from scripts.model import Candidate, ConversionError
from scripts.openvpn import parse_openvpn


def convert(nodes, skipped: Counter) -> list[Candidate]:
    result = []
    for node in nodes:
        try:
            for proxy in parse_openvpn(node.ovpn):
                result.append(Candidate(node, proxy))
        except ConversionError as exc:
            skipped[str(exc)] += 1
    return result


def generate(profiles, fetch_settings, output_dir: Path, client=None) -> dict:
    client = client or HttpClient(fetch_settings["timeout_seconds"], fetch_settings["retries"])
    skipped, warnings = Counter(), []
    candidates, csv_count, index_count = [], 0, 0
    protocols = set().union(*(p.protocols for p in profiles))
    countries = set().union(*(set(p.settings["countries"]) for p in profiles))
    if any(not p.settings["countries"] for p in profiles):
        countries = set()
    try:
        nodes, malformed = parse_csv(client.get(API_URL))
        csv_count = len(nodes)
        skipped["invalid CSV rows"] += malformed
        candidates.extend(convert(nodes, skipped))
    except ConversionError as exc:
        warnings.append(str(exc))
    known = {c.endpoint for c in candidates}
    try:
        nodes, failed, index_count = supplement(client, protocols, known, countries, fetch_settings["concurrency"])
        warnings.extend(failed)
        candidates.extend(convert(nodes, skipped))
    except ConversionError as exc:
        warnings.append(str(exc))
    if not candidates:
        raise ConversionError("no compatible nodes from official sources; existing outputs were retained")
    files, infos = {}, {}
    for profile in profiles:
        text, info = build_provider(profile, candidates)
        filename = f"{profile.name}.yaml"
        files[filename] = text
        infos[filename] = info
    status = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_csv_rows": csv_count, "source_index_rows": index_count,
        "warnings": dict(Counter(warnings)), "skipped": {k: v for k, v in skipped.items() if v},
        "runtime_connectivity_tested": False, "profiles": infos,
    }
    manifest = {"version": 1, "mihomo_validated": False,
                "files": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}}
    files["status.json"] = json.dumps(status, ensure_ascii=False, indent=2) + "\n"
    files["manifest.json"] = json.dumps(manifest, indent=2) + "\n"
    output_dir = output_dir.resolve()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    # Validate/build the entire batch before touching any existing output file.
    with tempfile.TemporaryDirectory(prefix="vpngate-build-", dir=output_dir.parent) as staging:
        for name, text in files.items():
            Path(staging, name).write_text(text, encoding="utf-8", newline="\n")
        output_dir.mkdir(exist_ok=True)
        for name in files:
            os.replace(Path(staging, name), output_dir / name)
    return status


def run(argv=None) -> int:
    try:
        args = arguments(argv)
        profiles, fetch_settings = resolve(args)
        status = generate(profiles, fetch_settings, args.output_dir)
    except ConversionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print("ERROR: invalid configuration or local I/O failure; no subscription was published", file=sys.stderr)
        return 1
    summary = ["## VPN Gate conversion", "", "| File | Nodes | Transports | Chained |",
               "| --- | ---: | --- | --- |"]
    for name, info in status["profiles"].items():
        summary.append(f"| {name} | {info['node_count']} | {','.join(info['protocols'])} | {info['chain_enabled']} |")
        print(f"Generated {name}: {info['node_count']} nodes ({','.join(info['protocols'])})")
    summary.extend(["", f"Source warnings: {sum(status['warnings'].values())}; skipped configurations: {sum(status['skipped'].values())}.",
                    "", "Configuration generation is complete. Real VPN connectivity has not been tested."])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("\n".join(summary) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
