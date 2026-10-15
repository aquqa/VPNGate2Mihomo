import base64
import csv
from datetime import datetime, timedelta, timezone
import io

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def materials():
    # Disposable keys are generated in memory; no source credentials are stored.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VPNGate2Mihomo test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


def ovpn(cert, key, proto="tcp", extra="", ip="203.0.113.10", port=1194):
    return (f"client\nproto {proto}\nremote {ip} {port}\ndev tun\ncipher AES-128-CBC\nauth SHA1\n"
            f"{extra}\n<ca>\n{cert}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n")


def csv_text(config):
    stream = io.StringIO(newline="")
    stream.write("*vpn_servers\n")
    writer = csv.writer(stream)
    writer.writerow(["#HostName", "IP", "Score", "Ping", "Speed", "CountryLong", "CountryShort", "OpenVPN_ConfigData_Base64"])
    writer.writerow(["vpn1", "203.0.113.10", "100", "20", "50000000", "Japan", "JP", base64.b64encode(config.encode()).decode()])
    stream.write("*\n")
    return stream.getvalue()


INDEX = """<table><tr>
<td><img src='../images/flags/JP.png'><br>Japan</td>
<td>vpn1.opengw.net<br>203.0.113.10</td><td>1 sessions</td>
<td>50.00 Mbps<br>Ping: 20 ms</td>
<td><a href='do_openvpn.aspx?fqdn=vpn1.opengw.net&amp;ip=203.0.113.10&amp;tcp=1194&amp;udp=1195&amp;sid=123&amp;hid=456'>OpenVPN</a></td>
<td>1,000</td></tr></table>"""
PAGE = """<a href='/common/openvpn_download.aspx?sid=123&amp;udp=1&amp;host=vpn1.opengw.net&amp;port=1195&amp;hid=456&amp;/vpngate_udp.ovpn'>DDNS</a>
<a href='/common/openvpn_download.aspx?sid=123&amp;udp=1&amp;host=203.0.113.10&amp;port=1195&amp;hid=456&amp;/vpngate_udp.ovpn'>IP</a>
<a href='/common/openvpn_download.aspx?sid=123&amp;tcp=1&amp;host=203.0.113.10&amp;port=1194&amp;hid=456&amp;/vpngate_tcp.ovpn'>TCP</a>"""


class FakeClient:
    def __init__(self, tcp, udp):
        self.tcp, self.udp = tcp, udp
        self.urls = []

    def get(self, url, max_bytes=8388608):
        self.urls.append(url)
        if "/api/iphone/" in url:
            return csv_text(self.tcp)
        if "do_openvpn.aspx" in url:
            return PAGE
        if "openvpn_download.aspx" in url:
            return self.udp if "udp=1" in url else self.tcp
        if url.endswith("/en/"):
            return INDEX
        raise AssertionError("unexpected URL")
