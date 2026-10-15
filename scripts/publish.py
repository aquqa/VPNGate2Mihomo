"""Fast-forward-only publication using an isolated Git index and one commit."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

BRANCH = "refs/heads/subscriptions"


class PublishError(ValueError):
    pass


def git(*args, data=None, env=None, check=True):
    result = subprocess.run(["git", *args], input=data, capture_output=True, env=env, timeout=120)
    if check and result.returncode:
        raise PublishError(f"git {args[0]} failed (exit {result.returncode}); check repository permissions and branch rules")
    return result


def remote_parent() -> str | None:
    result = git("ls-remote", "--exit-code", "--heads", "origin", BRANCH, check=False)
    if result.returncode == 2:
        return None
    if result.returncode:
        raise PublishError("cannot query publication branch")
    git("fetch", "--no-tags", "--depth=1", "origin", BRANCH)
    return git("rev-parse", "FETCH_HEAD").stdout.decode().strip()


def previous(parent, name):
    if parent is None:
        return None
    result = git("show", f"{parent}:{name}", check=False)
    return result.stdout if result.returncode == 0 else None


def load_batch(directory: Path):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or manifest.get("mihomo_validated") is not True:
        raise PublishError("publication requires a successfully Mihomo-validated manifest")
    entries = manifest.get("files")
    if not isinstance(entries, dict) or not 1 <= len(entries) <= 32:
        raise PublishError("invalid publication manifest")
    files = {}
    for name, expected in entries.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.yaml", name):
            raise PublishError("invalid publication filename")
        path = directory / name
        if path.is_symlink():
            raise PublishError("publication files must not be symlinks")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise PublishError("publication checksum mismatch")
        files[name] = content
    status = json.loads((directory / "status.json").read_text(encoding="utf-8"))
    if set(status.get("profiles", {})) != set(files):
        raise PublishError("profile status does not match the publication manifest")
    return files, status, manifest.get("validation_core", "unspecified")


def publish(directory: Path) -> bool:
    files, status, core_version = load_batch(directory)
    for attempt in range(3):
        parent = remote_parent()
        changed = {name: data for name, data in files.items() if previous(parent, name) != data}
        if not changed:
            print("Provider content unchanged; no commit created.")
            return False
        old = previous(parent, "status.json")
        stored = json.loads(old) if old else {"profiles": {}}
        if not isinstance(stored, dict) or not isinstance(stored.get("profiles"), dict):
            raise PublishError("existing publication status is invalid")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for name in changed:
            stored["profiles"][name] = dict(status["profiles"][name], last_content_update=now)
        stored["last_content_update"] = now
        stored["runtime_connectivity_tested"] = False
        stored["validation_core"] = core_version
        changed["status.json"] = (json.dumps(stored, ensure_ascii=False, indent=2) + "\n").encode()
        with tempfile.TemporaryDirectory(prefix="vpngate-git-index-") as temp:
            env = dict(os.environ, GIT_INDEX_FILE=str(Path(temp, "index")),
                       GIT_AUTHOR_NAME="github-actions[bot]", GIT_COMMITTER_NAME="github-actions[bot]",
                       GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
                       GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com")
            if parent:
                git("read-tree", parent, env=env)
            else:
                git("read-tree", "--empty", env=env)
            for name, data in changed.items():
                blob = git("hash-object", "-w", "--stdin", data=data, env=env).stdout.decode().strip()
                git("update-index", "--add", "--cacheinfo", f"100644,{blob},{name}", env=env)
            tree = git("write-tree", env=env).stdout.decode().strip()
            args = ["commit-tree", tree]
            if parent:
                args.extend(["-p", parent])
            commit = git(*args, data=b"Update VPN Gate subscriptions\n", env=env).stdout.decode().strip()
        # Normal pushes preserve remote-only commits and obey branch protection.
        pushed = git("push", "--porcelain", "origin", f"{commit}:{BRANCH}", check=False)
        if pushed.returncode == 0:
            print(f"Published {len(changed) - 1} provider file(s) to subscriptions.")
            return True
        new_parent = remote_parent()
        if new_parent == parent or attempt == 2:
            raise PublishError("push rejected; check contents: write and subscription branch rules")
    raise PublishError("publication could not complete")


def run(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)
    try:
        publish(args.directory)
    except (PublishError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, PublishError) else "publication failed; existing branch contents were retained"
        print(f"ERROR: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
