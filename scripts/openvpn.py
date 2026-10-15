"""Parse a deliberately bounded OpenVPN client subset; never execute options."""

import ipaddress
import re
import shlex
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.utils import CryptographyDeprecationWarning

from scripts.model import ConversionError

CIPHERS = {
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305",
}
AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass"}
# Native process/interface settings do not apply to a Mihomo proxy outbound.
IGNORED = {
    "client", "tls-client", "resolv-retry", "nobind", "persist-key", "persist-tun",
    "verb", "mute", "auth-nocache", "connect-retry", "connect-retry-max",
    "connect-timeout", "remote-random", "route", "route-ipv6", "route-nopull",
    "redirect-gateway", "redirect-private", "dhcp-option", "pull", "explicit-exit-notify",
    "sndbuf", "rcvbuf", "fast-io", "mute-replay-warnings",
}
SINGLE = {
    "proto", "dev", "cipher", "auth", "data-ciphers", "data-ciphers-fallback",
    "comp-lzo", "key-direction", "ping", "ping-restart", "tun-mtu", "port", "rport",
    "hand-window", "tran-window",
}


def normalize_proto(value: str) -> str:
    if value in {"tcp", "tcp-client", "tcp4", "tcp4-client"}:
        return "tcp"
    if value in {"udp", "udp4"}:
        return "udp"
    raise ConversionError("unsupported transport protocol")


def normalize_cipher(value: str) -> str:
    result = value.upper()
    if result == "AES-CBC":
        result = "AES-128-CBC"
    if result not in CIPHERS:
        raise ConversionError("unsupported data cipher")
    return result


def integer(value: str, label: str, minimum: int = 0, maximum: int = 86400) -> int:
    try:
        result = int(value)
    except (ValueError, TypeError):
        raise ConversionError(f"invalid {label}") from None
    if not minimum <= result <= maximum:
        raise ConversionError(f"invalid {label}")
    return result


def validate_material(blocks: dict[str, str]) -> None:
    if "ca" not in blocks:
        raise ConversionError("missing inline CA certificate")
    try:
        if not x509.load_pem_x509_certificates(blocks["ca"].encode()):
            raise ValueError
        has_cert, has_key = "cert" in blocks, "key" in blocks
        if has_cert != has_key:
            raise ConversionError("client certificate and key must both be present")
        if has_cert:
            # VPN Gate's shared legacy client certificate has a non-positive
            # serial. The pinned parser accepts it; suppress this one known
            # deprecation without disabling any certificate/key checks.
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive.*",
                                        category=CryptographyDeprecationWarning)
                certificates = x509.load_pem_x509_certificates(blocks["cert"].encode())
            if not certificates:
                raise ValueError
            key = serialization.load_pem_private_key(blocks["key"].encode(), password=None)
            encoding = serialization.Encoding.DER
            fmt = serialization.PublicFormat.SubjectPublicKeyInfo
            if certificates[0].public_key().public_bytes(encoding, fmt) != key.public_key().public_bytes(encoding, fmt):
                raise ConversionError("client certificate and key do not match")
    except ConversionError:
        raise
    except (ValueError, TypeError):
        raise ConversionError("invalid or encrypted certificate/key material") from None
    active = [key for key in ("tls-auth", "tls-crypt", "tls-crypt-v2") if key in blocks]
    if len(active) > 1:
        raise ConversionError("conflicting TLS control-channel keys")
    for name in active:
        if name == "tls-crypt-v2":
            if "-----BEGIN OpenVPN tls-crypt-v2 client key-----" not in blocks[name]:
                raise ConversionError("invalid tls-crypt-v2 block")
        else:
            lines = [line.strip() for line in blocks[name].splitlines()
                     if line.strip() and not line.startswith(("#", "-----"))]
            try:
                raw = bytes.fromhex("".join(lines))
            except ValueError:
                raise ConversionError("invalid TLS static key") from None
            if len(raw) != 256:
                raise ConversionError("invalid TLS static key length")


def parse_openvpn(text: str) -> list[dict]:
    if len(text.encode("utf-8")) > 262144 or "\x00" in text:
        raise ConversionError("invalid OpenVPN document size or encoding")
    options: dict[str, list[str]] = {}
    blocks: dict[str, str] = {}
    remotes: list[list[str]] = []
    declared_inline = set()
    auth_user_pass = False
    lines = iter(text.lstrip("\ufeff").splitlines())
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        match = re.fullmatch(r"<([a-zA-Z0-9_-]+)>", line)
        if match:
            name = match[1].lower()
            if name not in BLOCKS or name in blocks:
                raise ConversionError("unsupported or duplicate inline block")
            content = []
            for inner in lines:
                if inner.strip() == f"</{name}>":
                    break
                if re.fullmatch(r"</?[a-zA-Z0-9_-]+>", inner.strip()):
                    raise ConversionError("nested or mismatched inline block")
                content.append(inner)
            else:
                raise ConversionError("unterminated inline block")
            blocks[name] = "\n".join(content).strip() + "\n"
            continue
        try:
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#;"
            words = list(lexer)
        except ValueError:
            raise ConversionError("invalid directive quoting") from None
        if not words:
            continue
        name, args = words[0].removeprefix("--").lower(), words[1:]
        if name == "remote":
            if not 1 <= len(args) <= 3:
                raise ConversionError("invalid remote directive")
            remotes.append(args)
        elif name in SINGLE:
            if name == "comp-lzo" and not args:
                args = ["adaptive"]
            if len(args) != 1:
                raise ConversionError("invalid single-value directive")
            options[name] = args
        elif name in {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}:
            if not args or args[0] != "[inline]" or len(args) > (2 if name == "tls-auth" else 1):
                raise ConversionError("external certificate/key files are unsupported")
            declared_inline.add(name)
            if name == "tls-auth" and len(args) == 2:
                options["key-direction"] = [args[1]]
        elif name == "auth-user-pass":
            if args and args != ["[inline]"]:
                raise ConversionError("external credentials files are unsupported")
            auth_user_pass = True
        elif name == "remote-cert-tls" and args == ["server"]:
            # The pinned Mihomo client verifies CA trust and ServerAuth EKU.
            continue
        elif name == "keepalive" and len(args) == 2:
            options["ping"], options["ping-restart"] = [args[0]], [args[1]]
        elif name not in IGNORED:
            # In particular, never silently discard verification constraints,
            # scripts, plugins, file includes, or unknown cipher negotiation.
            safe_name = name if re.fullmatch(r"[a-z0-9-]{1,64}", name) else "unknown"
            raise ConversionError(f"unsupported directive: {safe_name}")
    if not remotes:
        raise ConversionError("missing remote endpoint")
    if not declared_inline.issubset(blocks):
        raise ConversionError("declared inline certificate/key block is missing")
    validate_material(blocks)
    if "cert" not in blocks and not auth_user_pass and "auth-user-pass" not in blocks:
        raise ConversionError("missing client authentication")
    get = lambda key, default="": options.get(key, [default])[0]
    if get("dev", "tun") != "tun":
        raise ConversionError("only dev tun is supported")
    cipher_list = [normalize_cipher(item) for item in get("data-ciphers").split(":") if item]
    cipher = normalize_cipher(get("cipher") or (cipher_list[0] if cipher_list else ""))
    auth = get("auth", "SHA1").upper().replace("SHA-1", "SHA1")
    if auth not in AUTH:
        raise ConversionError("unsupported authentication digest")
    common = {"type": "openvpn", "dev": "tun", "cipher": cipher,
              "auth": auth, "data-ciphers": cipher_list or [cipher]}
    common.update({name: value for name, value in blocks.items() if name != "auth-user-pass"})
    if auth_user_pass or "auth-user-pass" in blocks:
        credentials = blocks.get("auth-user-pass", "vpn\nvpn\n").splitlines()
        if len(credentials) != 2 or not all(credentials):
            raise ConversionError("invalid inline credentials")
        common.update(username=credentials[0], password=credentials[1])
    if get("data-ciphers-fallback"):
        common["data-ciphers-fallback"] = normalize_cipher(get("data-ciphers-fallback"))
    if get("comp-lzo"):
        if get("comp-lzo") not in {"yes", "no", "adaptive"}:
            raise ConversionError("unsupported comp-lzo mode")
        common["comp-lzo"] = get("comp-lzo")
    if get("key-direction"):
        if get("key-direction") not in {"0", "1"}:
            raise ConversionError("invalid key direction")
        common["key-direction"] = get("key-direction")
    for source, target in (("ping", "ping"), ("ping-restart", "ping-restart"),
                           ("hand-window", "handshake-timeout"), ("tran-window", "tran-window")):
        if source in options:
            common[target] = integer(get(source), source)
    if "tun-mtu" in options:
        common["mtu"] = integer(get("tun-mtu"), "MTU", 576, 65535)
    result = []
    for args in remotes:
        host = args[0].rstrip(".").lower()
        try:
            host = str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
                raise ConversionError("invalid remote hostname") from None
        port = integer(args[1] if len(args) > 1 else get("rport", get("port", "1194")), "port", 1, 65535)
        proto = normalize_proto(args[2] if len(args) > 2 else get("proto", "udp"))
        result.append(dict(common, server=host, port=port, proto=proto))
    return result
