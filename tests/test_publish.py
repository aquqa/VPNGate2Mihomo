import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.publish import load_batch, publish, PublishError


@unittest.skipUnless(shutil.which("git"), "Git is required for publication integration tests")
class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.remote = self.root / "remote.git"
        self.batch = self.root / "batch"
        self.repo.mkdir()
        self.batch.mkdir()
        self.git("init", "--bare", str(self.remote), cwd=self.root)
        self.git("init", str(self.repo), cwd=self.root)
        self.git("config", "user.name", "Test", cwd=self.repo)
        self.git("config", "user.email", "test@example.invalid", cwd=self.repo)
        self.git("config", "core.autocrlf", "false", cwd=self.repo)
        (self.repo / "source.txt").write_text("source must remain unchanged\n", encoding="utf-8")
        self.git("add", "source.txt", cwd=self.repo)
        self.git("commit", "-m", "Initial source", cwd=self.repo)
        self.git("remote", "add", "origin", str(self.remote), cwd=self.repo)
        self.old_cwd = Path.cwd()
        os.chdir(self.repo)

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.temp.cleanup()

    @staticmethod
    def git(*args, cwd=None):
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)
        return result.stdout.decode().strip()

    def make_batch(self, files, validated=True):
        entries, infos = {}, {}
        for name, content in files.items():
            data = content.encode()
            (self.batch / name).write_bytes(data)
            entries[name] = hashlib.sha256(data).hexdigest()
            infos[name] = {"node_count": 1, "sha256": entries[name]}
        (self.batch / "manifest.json").write_text(json.dumps({"version": 1, "mihomo_validated": validated, "files": entries}), encoding="utf-8")
        (self.batch / "status.json").write_text(json.dumps({"profiles": infos}), encoding="utf-8")

    def remote_head(self):
        return self.git("--git-dir", str(self.remote), "rev-parse", "refs/heads/subscriptions")

    def test_initial_publish_has_only_deliverables_and_preserves_source(self):
        self.make_batch({"tcp.yaml": "proxies: [tcp]\n"})
        before = self.git("status", "--porcelain")
        self.assertTrue(publish(self.batch))
        names = self.git("--git-dir", str(self.remote), "ls-tree", "--name-only", "subscriptions").splitlines()
        self.assertEqual(set(names), {"tcp.yaml", "status.json"})
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual((self.repo / "source.txt").read_text(), "source must remain unchanged\n")

    def test_unchanged_content_does_not_create_a_commit(self):
        self.make_batch({"tcp.yaml": "proxies: [tcp]\n"})
        publish(self.batch)
        first = self.remote_head()
        self.assertFalse(publish(self.batch))
        self.assertEqual(self.remote_head(), first)

    def test_partial_update_preserves_unselected_files(self):
        self.make_batch({"tcp.yaml": "tcp-v1\n", "udp.yaml": "udp-v1\n"})
        publish(self.batch)
        first = self.remote_head()
        self.make_batch({"tcp-chain.yaml": "tcp-chain-v1\n"})
        publish(self.batch)
        self.assertEqual(self.git("--git-dir", str(self.remote), "show", "subscriptions:udp.yaml"), "udp-v1")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "subscriptions^"), first)
        status = json.loads(self.git("--git-dir", str(self.remote), "show", "subscriptions:status.json"))
        self.assertEqual(set(status["profiles"]), {"tcp.yaml", "udp.yaml", "tcp-chain.yaml"})

    def test_unvalidated_or_modified_artifact_cannot_publish(self):
        self.make_batch({"tcp.yaml": "valid\n"}, validated=False)
        with self.assertRaises(PublishError):
            publish(self.batch)
        self.make_batch({"tcp.yaml": "valid\n"})
        (self.batch / "tcp.yaml").write_text("tampered", encoding="utf-8")
        with self.assertRaises(PublishError):
            publish(self.batch)

    def test_publish_rejection_preserves_remote_head(self):
        self.make_batch({"tcp.yaml": "v1\n"})
        publish(self.batch)
        first = self.remote_head()
        self.make_batch({"tcp.yaml": "v2\n"})
        from scripts import publish as module
        original_git = module.git
        def reject(*args, **kwargs):
            if args[0] == "push":
                return subprocess.CompletedProcess(args, 1, b"", b"permission denied")
            return original_git(*args, **kwargs)
        with patch("scripts.publish.git", side_effect=reject), self.assertRaises(PublishError):
            publish(self.batch)
        self.assertEqual(self.remote_head(), first)

    def test_concurrent_commit_is_preserved_on_retry(self):
        self.make_batch({"tcp.yaml": "v1\n"})
        publish(self.batch)
        self.make_batch({"tcp.yaml": "v2\n"})
        from scripts import publish as module
        original_git = module.git
        raced = False
        def insert_concurrent_commit(*args, **kwargs):
            nonlocal raced
            if args[0] == "push" and not raced:
                raced = True
                parent = self.remote_head()
                with tempfile.TemporaryDirectory(dir=self.root) as temp:
                    env = dict(os.environ, GIT_INDEX_FILE=str(Path(temp, "index")))
                    original_git("read-tree", parent, env=env)
                    blob = original_git("hash-object", "-w", "--stdin", data=b"concurrent file\n", env=env).stdout.decode().strip()
                    original_git("update-index", "--add", "--cacheinfo", f"100644,{blob},other.yaml", env=env)
                    tree = original_git("write-tree", env=env).stdout.decode().strip()
                    commit = original_git("commit-tree", tree, "-p", parent, data=b"Concurrent update\n", env=env).stdout.decode().strip()
                    original_git("push", "origin", f"{commit}:refs/heads/subscriptions")
            return original_git(*args, **kwargs)
        with patch("scripts.publish.git", side_effect=insert_concurrent_commit):
            self.assertTrue(publish(self.batch))
        self.assertTrue(raced)
        self.assertEqual(self.git("--git-dir", str(self.remote), "show", "subscriptions:other.yaml"), "concurrent file")
        self.assertEqual(self.git("--git-dir", str(self.remote), "show", "subscriptions:tcp.yaml"), "v2")

    def test_path_traversal_manifest_is_rejected(self):
        (self.batch / "manifest.json").write_text(json.dumps({"version": 1, "mihomo_validated": True, "files": {"../escape.yaml": "hash"}}), encoding="utf-8")
        with self.assertRaises(PublishError):
            load_batch(self.batch)
