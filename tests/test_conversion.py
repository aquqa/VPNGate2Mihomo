from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts.config import arguments, resolve, validate_profile, DEFAULT, merge
from scripts.fetch import parse_csv, IndexParser, DownloadParser, official_url, supplement
from scripts.main import convert, generate
from scripts.mihomo import build_provider
from scripts.model import Candidate, ConversionError, SourceNode
from scripts.openvpn import parse_openvpn
from scripts.validate import validate, load_manifest
from tests.helpers import FakeClient, INDEX, PAGE, csv_text, materials, ovpn


class ConversionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = materials()
        cls.text = ovpn(cls.cert, cls.key)

    def test_real_fields_and_material_are_preserved(self):
        proxy = parse_openvpn(self.text)[0]
        self.assertEqual((proxy["proto"], proxy["port"], proxy["cipher"], proxy["auth"]),
                         ("tcp", 1194, "AES-128-CBC", "SHA1"))
        self.assertEqual(proxy["key"], self.key)
        self.assertNotIn("udp", proxy)

    def test_transport_is_not_inferred_from_udp_capability(self):
        self.assertEqual(parse_openvpn(self.text.replace("proto tcp", "proto tcp-client"))[0]["proto"], "tcp")

    def test_multiple_remotes_and_per_remote_transport(self):
        proxies = parse_openvpn(self.text + "remote 203.0.113.11 1195 udp\n")
        self.assertEqual([(p["port"], p["proto"]) for p in proxies], [(1194, "tcp"), (1195, "udp")])

    def test_auth_default_matches_openvpn_not_mihomo(self):
        self.assertEqual(parse_openvpn(self.text.replace("auth SHA1\n", ""))[0]["auth"], "SHA1")

    def test_cipher_negotiation_and_fallback(self):
        proxy = parse_openvpn(self.text + "data-ciphers AES-256-GCM:AES-128-CBC\ndata-ciphers-fallback AES-128-CBC\n")[0]
        self.assertEqual(proxy["data-ciphers"], ["AES-256-GCM", "AES-128-CBC"])
        self.assertEqual(proxy["data-ciphers-fallback"], "AES-128-CBC")

    def test_missing_cipher_is_not_guessed(self):
        with self.assertRaises(ConversionError):
            parse_openvpn(self.text.replace("cipher AES-128-CBC\n", ""))

    def test_unsupported_security_and_execution_options_are_rejected(self):
        for directive in ("up stolen.sh", "config other.ovpn", "verify-x509-name vpn name", "compress lz4"):
            with self.subTest(directive=directive), self.assertRaises(ConversionError):
                parse_openvpn(self.text + directive + "\n")

    def test_script_like_text_in_comments_is_not_executed(self):
        self.assertEqual(parse_openvpn(self.text + "# up stolen.sh\n")[0]["proto"], "tcp")

    def test_missing_or_mismatched_key_is_rejected(self):
        other_cert, other_key = materials()
        with self.assertRaises(ConversionError):
            parse_openvpn(self.text.replace(self.key, other_key))
        with self.assertRaises(ConversionError):
            parse_openvpn(self.text.replace(f"<key>\n{self.key}</key>\n", ""))

    def test_malformed_material_never_leaks_in_error(self):
        damaged = self.text.replace(self.key, "PRIVATE_SENTINEL\n")
        with self.assertRaises(ConversionError) as caught:
            parse_openvpn(damaged)
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_bad_port_tap_and_unterminated_blocks(self):
        for text in (self.text.replace("1194", "65536"), self.text.replace("dev tun", "dev tap"), self.text.replace("</key>", "")):
            with self.subTest(), self.assertRaises(ConversionError):
                parse_openvpn(text)

    def test_declared_inline_key_must_be_present(self):
        with self.assertRaises(ConversionError):
            parse_openvpn(self.text + "tls-auth [inline] 1\n")

    def test_public_vpngate_password_auth_when_required(self):
        text = self.text[:self.text.index("<cert>")] + "auth-user-pass\n"
        proxy = parse_openvpn(text)[0]
        self.assertEqual((proxy["username"], proxy["password"]), ("vpn", "vpn"))
        self.assertNotIn("key", proxy)

    def test_inline_credentials(self):
        text = self.text[:self.text.index("<cert>")] + "<auth-user-pass>\nuser\npass\n</auth-user-pass>\n"
        self.assertEqual(parse_openvpn(text)[0]["username"], "user")

    def test_csv_base64_and_partial_invalid_rows(self):
        text = csv_text(self.text)
        nodes, rejected = parse_csv(text)
        self.assertEqual((len(nodes), rejected, nodes[0].ovpn), (1, 0, self.text))
        broken_row = "bad,invalid,0,0,0,Unknown,ZZ,invalid-base64\n"
        nodes, rejected = parse_csv(text.replace("*\n", broken_row + "*\n"))
        self.assertEqual((len(nodes), rejected), (1, 1))

    def test_csv_abnormal_page_is_rejected(self):
        with self.assertRaises(ConversionError):
            parse_csv("<html>blocked</html>")

    def test_index_metadata_and_dynamic_download_links(self):
        index = IndexParser()
        index.feed(INDEX)
        _, node, ports = index.pages[0]
        self.assertEqual((node.country, node.score, node.speed, ports["udp"]), ("JP", 1000, 50000000, 1195))
        page = DownloadParser()
        page.feed(PAGE)
        self.assertEqual(len(page.links), 3)
        self.assertNotIn("&amp;", page.links[0])

    def test_udp_download_uses_actual_configuration(self):
        udp = ovpn(self.cert, self.key, "udp", port=1195)
        client = FakeClient(self.text, udp)
        nodes, warnings, count = supplement(client, {"tcp", "udp"}, {("203.0.113.10", 1194, "tcp")}, set(), 2)
        self.assertEqual((len(nodes), warnings, count), (1, [], 1))
        self.assertEqual(parse_openvpn(nodes[0].ovpn)[0]["port"], 1195)
        self.assertTrue(any("sid=123" in url and "host=203.0.113.10" in url for url in client.urls))

    def test_untrusted_origins_and_downgrades_are_rejected(self):
        for url in ("http://www.vpngate.net/en/", "https://example.com/en/", "https://user:secret@www.vpngate.net/en/"):
            with self.subTest(url=url), self.assertRaises(ConversionError):
                official_url(url)

    def candidates(self):
        nodes = [SourceNode("vpn1", "203.0.113.10", "JP", score=100, ovpn=self.text),
                 SourceNode("vpn1", "203.0.113.10", "JP", score=100, ovpn=ovpn(self.cert, self.key, "udp", port=1195))]
        return convert(nodes, Counter())

    def test_dedup_stable_serialization_and_pem_roundtrip(self):
        profile = validate_profile("all", merge(DEFAULT, {}))
        candidates = self.candidates()
        first, info = build_provider(profile, candidates + candidates)
        second, _ = build_provider(profile, list(reversed(candidates)))
        self.assertEqual(first, second)
        self.assertEqual(info["node_count"], 2)
        self.assertEqual(yaml.safe_load(first)["proxies"][0]["key"], self.key)
        self.assertIn("key: |", first)

    def test_chain_and_direct_exports(self):
        profile = validate_profile("tcp-chain", merge(DEFAULT, {"protocol": "tcp", "chain": {"enabled": True, "dialer_proxy": '代理 "$(echo text)"'}}))
        text, _ = build_provider(profile, self.candidates())
        self.assertEqual(yaml.safe_load(text)["proxies"][0]["dialer-proxy"], '代理 "$(echo text)"')
        direct, _ = build_provider(validate_profile("tcp", merge(DEFAULT, {"protocol": "tcp"})), self.candidates())
        self.assertNotIn("dialer-proxy", yaml.safe_load(direct)["proxies"][0])

    def test_country_filter_empty_result_fails(self):
        profile = validate_profile("us", merge(DEFAULT, {"countries": ["US"]}))
        with self.assertRaises(ConversionError):
            build_provider(profile, self.candidates())

    def test_mixed_limit_retains_each_transport(self):
        candidates = self.candidates()
        for i in range(3):
            proxy = dict(candidates[0].proxy, server=f"203.0.113.{20 + i}")
            candidates.append(Candidate(replace(candidates[0].source, score=1000), proxy))
        text, _ = build_provider(validate_profile("all", merge(DEFAULT, {"max_nodes": 2})), candidates)
        self.assertEqual({p["proto"] for p in yaml.safe_load(text)["proxies"]}, {"tcp", "udp"})

    def test_generation_and_core_validation_manifest_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp, "dist")
            profile = validate_profile("all", merge(DEFAULT, {}))
            generate([profile], {"timeout_seconds": 1, "retries": 1, "concurrency": 1}, directory,
                     FakeClient(self.text, ovpn(self.cert, self.key, "udp", port=1195)))
            self.assertFalse(load_manifest(directory)["mihomo_validated"])
            with patch("scripts.validate.subprocess.run") as run:
                run.return_value.returncode = 1
                run.return_value.stdout = b"Mihomo Meta v1.19.32 windows amd64"
                with self.assertRaises(ConversionError):
                    validate(directory, Path("fake-core"))
                self.assertFalse(load_manifest(directory)["mihomo_validated"])
                run.return_value.returncode = 0
                validate(directory, Path("fake-core"))
                self.assertTrue(load_manifest(directory)["mihomo_validated"])

    def test_failed_refresh_retains_existing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp, "dist")
            directory.mkdir()
            old = directory / "udp.yaml"
            old.write_text("existing snapshot", encoding="utf-8")
            profile = validate_profile("udp", merge(DEFAULT, {"protocol": "udp"}))
            with self.assertRaises(ConversionError):
                generate([profile], {"timeout_seconds": 1, "retries": 1, "concurrency": 1}, directory,
                         FakeClient(self.text, "<html>error</html>"))
            self.assertEqual(old.read_text(encoding="utf-8"), "existing snapshot")
            self.assertFalse((directory / "manifest.json").exists())


class ConfigTests(unittest.TestCase):
    def resolve_config(self, text, argv=None, env=None):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "config.yaml")
            path.write_text(text, encoding="utf-8")
            return resolve(arguments(["--config", str(path), *(argv or [])], env or {}))

    BASE = 'version: 1\ndefaults:\n  protocol: tcp\n  chain:\n    enabled: true\n    dialer_proxy: 前置代理\nprofiles:\n  chained: {}\n'

    def test_scheduled_defaults_and_env_override(self):
        profiles, _ = self.resolve_config(self.BASE)
        self.assertEqual(profiles[0].name, "chained")
        profiles, _ = self.resolve_config(self.BASE, env={"INPUT_PROTOCOL": "udp", "INPUT_CHAIN": "off"})
        self.assertEqual(profiles[0].name, "udp")
        self.assertFalse(profiles[0].settings["chain"]["enabled"])

    def test_cli_precedes_environment_including_zero(self):
        profiles, _ = self.resolve_config(self.BASE, ["--protocol", "tcp", "--max-nodes", "0"], {"INPUT_PROTOCOL": "udp"})
        self.assertEqual(profiles[0].settings["max_nodes"], 0)
        self.assertEqual(profiles[0].settings["protocol"], "tcp")

    def test_chain_cli_shorthand_and_missing_group(self):
        config = 'version: 1\nprofiles:\n  all: {}\n'
        profiles, _ = self.resolve_config(config, ["--protocol", "tcp", "--dialer-proxy", "前置"])
        self.assertEqual(profiles[0].name, "tcp-chain")
        with self.assertRaises(ConversionError):
            self.resolve_config(config, ["--chain", "on"])

    def test_country_clear_and_profile_selection(self):
        profiles, _ = self.resolve_config(self.BASE.replace("protocol: tcp", "protocol: tcp\n  countries: [JP]"), ["--countries", "*", "--profile", "chained"])
        self.assertEqual(profiles[0].settings["countries"], [])
        self.assertEqual(profiles[0].name, "chained")

    def test_duplicate_keys_and_invalid_paths(self):
        for text in ('version: 1\nversion: 1\n', 'version: 1\nprofiles:\n  ../escape: {}\n'):
            with self.subTest(), self.assertRaises(ConversionError):
                self.resolve_config(text)
