"""Validate exported providers with a pinned Mihomo binary, without VPN dialing."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

import yaml

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.model import ConversionError

VERSION = "v1.19.32"
# Digests obtained from the official release's GitHub asset metadata.
ASSETS = {
    "Linux": ("mihomo-linux-amd64-compatible-v1.19.32.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"),
    "Windows": ("mihomo-windows-amd64-compatible-v1.19.32.zip", "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"),
}


def download_binary(directory: Path) -> Path:
    system = platform.system()
    if system not in ASSETS or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ConversionError("automatic Mihomo download supports Linux/Windows x86-64; use --binary")
    asset, expected = ASSETS[system]
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{asset}"
    request = urllib.request.Request(url, headers={"User-Agent": "VPNGate2Mihomo-validator"})
    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read(104857601)
    if len(data) > 104857600 or hashlib.sha256(data).hexdigest() != expected:
        raise ConversionError("Mihomo release archive checksum mismatch")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ("mihomo.exe" if system == "Windows" else "mihomo")
    if system == "Windows":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [info for info in archive.infolist() if info.filename.endswith(".exe")]
            if len(members) != 1 or members[0].file_size > 209715200:
                raise ConversionError("unexpected Mihomo release archive")
            executable = archive.read(members[0])
    else:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
            executable = archive.read(209715201)
        if len(executable) > 209715200:
            raise ConversionError("Mihomo executable exceeds size limit")
    target.write_bytes(executable)
    if system != "Windows":
        target.chmod(0o755)
    return target.resolve()


def load_manifest(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or not isinstance(manifest.get("files"), dict) or not 1 <= len(manifest["files"]) <= 32:
        raise ConversionError("invalid output manifest")
    for name, expected in manifest["files"].items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.yaml", name):
            raise ConversionError("invalid provider filename in manifest")
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ConversionError("provider file checksum mismatch")
    return manifest


def validate(directory: Path, binary: Path) -> None:
    manifest = load_manifest(directory)
    version_result = subprocess.run([str(binary.resolve()), "-v"], capture_output=True, timeout=15)
    version_match = re.search(rb"\bv\d+\.\d+\.\d+\b", version_result.stdout)
    if version_result.returncode or not version_match:
        raise ConversionError("cannot determine validation core version")
    core_version = version_match[0].decode("ascii")
    for name in manifest["files"]:
        provider = yaml.safe_load((directory / name).read_text(encoding="utf-8"))
        if not isinstance(provider, dict) or set(provider) != {"proxies"} or not provider["proxies"]:
            raise ConversionError("invalid provider document")
        proxies = provider["proxies"]
        references = sorted({p["dialer-proxy"] for p in proxies if p.get("dialer-proxy")})
        # Existing client-side groups cannot be known on a GitHub runner. Stub
        # them only for schema validation; no endpoint connections are made.
        config = {"mode": "rule", "log-level": "error", "proxies": proxies,
                  "proxy-groups": [{"name": ref, "type": "select", "proxies": ["DIRECT"]} for ref in references],
                  "rules": ["MATCH,DIRECT"]}
        with tempfile.TemporaryDirectory(prefix="vpngate-mihomo-") as temp:
            path = Path(temp, "config.yaml")
            path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
            result = subprocess.run([str(binary.resolve()), "-t", "-d", temp, "-f", str(path)],
                                    capture_output=True, timeout=120)
            if result.returncode:
                # Do not echo arbitrary core output containing imported key material.
                raise ConversionError(f"Mihomo rejected {name}; verify target-core compatibility")
        print(f"Mihomo configuration check passed: {name}")
    manifest["mihomo_validated"] = True
    manifest["validation_core"] = core_version
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def run(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--tools-dir", type=Path, default=Path(".tools"))
    args = parser.parse_args(argv)
    try:
        if args.binary and args.download:
            raise ConversionError("choose --binary or --download")
        binary = download_binary(args.tools_dir) if args.download else args.binary
        if binary is None:
            raise ConversionError("provide --binary or --download")
        validate(args.directory, binary)
    except ConversionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("ERROR: validator could not complete; publication is blocked", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
