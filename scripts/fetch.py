"""Official HTTPS sources only, with bounded requests and dynamic download URLs."""

import base64
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import replace
from html.parser import HTMLParser
import io
import ipaddress
from http.client import HTTPException
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from scripts.model import ConversionError, SourceNode

API_URL = "https://www.vpngate.net/api/iphone/"
INDEX_URL = "https://www.vpngate.net/en/"
csv.field_size_limit(1048576)


def official_url(url: str) -> str:
    parsed = urlsplit(url)
    try:
        valid = (parsed.scheme == "https" and parsed.hostname in {"www.vpngate.net", "vpngate.net"}
                 and parsed.port in {None, 443} and not parsed.username and not parsed.password)
    except ValueError:
        valid = False
    if not valid:
        raise ConversionError("source URL must be on the official HTTPS origin")
    return url


class OfficialRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpClient:
    def __init__(self, timeout: int = 30, retries: int = 3):
        self.timeout, self.retries = timeout, retries

    def get(self, url: str, max_bytes: int = 8388608) -> str:
        official_url(url)
        for attempt in range(self.retries):
            try:
                request = Request(url, headers={
                    "User-Agent": "VPNGate2Mihomo/1.0 (+GitHub Actions; public VPN Gate client)",
                    "Accept-Encoding": "identity",
                })
                with build_opener(OfficialRedirect()).open(request, timeout=self.timeout) as response:
                    official_url(response.url)
                    body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise ConversionError("source response exceeds size limit")
                return body.decode("utf-8-sig")
            except (HTTPError, URLError, TimeoutError, OSError, HTTPException):
                if attempt + 1 < self.retries:
                    time.sleep(min(2 ** attempt, 4))
            except UnicodeError:
                raise ConversionError("source response is not UTF-8") from None
        raise ConversionError("official source request failed after retries")


def number(value: str | None, default: int = 0) -> int:
    try:
        return max(0, int(value or ""))
    except ValueError:
        return default


def parse_csv(text: str) -> tuple[list[SourceNode], int]:
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.startswith("#HostName,")), None)
    if start is None or not text.lstrip("\ufeff").startswith("*vpn_servers"):
        raise ConversionError("unexpected CSV response or missing header")
    data = "".join([lines[start].removeprefix("#"), *lines[start + 1:]])
    reader = csv.DictReader(io.StringIO(data), strict=True)
    required = {"HostName", "IP", "CountryShort", "OpenVPN_ConfigData_Base64"}
    if not required.issubset(reader.fieldnames or []):
        raise ConversionError("missing required CSV columns")
    nodes, rejected = [], 0
    try:
        for row in reader:
            if (row.get("HostName") or "").startswith(("*", "#")):
                continue
            try:
                ip = str(ipaddress.ip_address(row["IP"]))
                encoded = row["OpenVPN_ConfigData_Base64"]
                if not encoded or len(encoded) > 350000:
                    raise ValueError
                ovpn = base64.b64decode(encoded, validate=True).decode("utf-8-sig")
                country = row["CountryShort"].upper()
                if not re.fullmatch(r"[A-Z]{2}", country):
                    raise ValueError
                nodes.append(SourceNode(
                    hostname=row["HostName"], ip=ip, country=country,
                    country_name=row.get("CountryLong") or country,
                    score=number(row.get("Score")), speed=number(row.get("Speed")),
                    ping=number(row.get("Ping"), -1), ovpn=ovpn,
                ))
            except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
                rejected += 1
    except csv.Error:
        raise ConversionError("malformed CSV document") from None
    if not nodes:
        raise ConversionError("CSV contains no decodable nodes")
    return nodes, rejected


class IndexParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pages: list[tuple[str, SourceNode, dict[str, int]]] = []
        self.cells: list[str] = []
        self.cell: list[str] | None = None
        self.country = "ZZ"
        self.link = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "tr":
            self.cells, self.cell, self.country, self.link = [], None, "ZZ", ""
        elif tag == "td":
            self.cell = []
        elif tag == "br" and self.cell is not None:
            self.cell.append(" ")
        elif tag == "img":
            match = re.search(r"/flags/([A-Za-z]{2})\.png", attrs.get("src", ""))
            if match:
                self.country = match[1].upper()
        elif tag == "a":
            url = urljoin(INDEX_URL, attrs.get("href", ""))
            if urlsplit(url).path == "/en/do_openvpn.aspx":
                self.link = official_url(url)

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "td" and self.cell is not None:
            self.cells.append(" ".join("".join(self.cell).split()))
            self.cell = None
        if tag != "tr" or not self.link:
            return
        query = parse_qs(urlsplit(self.link).query)
        try:
            ip = str(ipaddress.ip_address(query["ip"][0]))
            hostname = query["fqdn"][0]
            ports = {proto: number(query.get(proto, ["0"])[0]) for proto in ("tcp", "udp")}
            text = " ".join(self.cells)
            speed = re.search(r"([\d.]+)\s*Mbps", text)
            ping = re.search(r"Ping:\s*(\d+)\s*ms", text)
            node = SourceNode(hostname=hostname.removesuffix(".opengw.net"), ip=ip,
                              country=self.country, country_name=self.cells[0] if self.cells else self.country,
                              score=number(self.cells[-1].replace(",", "")) if self.cells else 0,
                              speed=int(float(speed[1]) * 1000000) if speed else 0,
                              ping=int(ping[1]) if ping else None)
            self.pages.append((self.link, node, ports))
        except (KeyError, ValueError, IndexError):
            return


class DownloadParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            url = urljoin(INDEX_URL, dict(attrs).get("href", ""))
            if urlsplit(url).path == "/common/openvpn_download.aspx":
                self.links.append(official_url(url))


def supplement(client: HttpClient, protocols: set[str], known: set[tuple],
               countries: set[str], concurrency: int) -> tuple[list[SourceNode], list[str], int]:
    index = IndexParser()
    index.feed(client.get(INDEX_URL))
    if not index.pages:
        raise ConversionError("official download index has no recognized entries")
    jobs = []
    seen = set()
    for url, node, ports in index.pages:
        if countries and node.country not in countries:
            continue
        wanted = {proto for proto in protocols if ports[proto] > 0
                  and (node.ip, ports[proto], proto) not in known}
        if wanted and url not in seen:
            seen.add(url)
            jobs.append((url, node, wanted))

    def download(job):
        url, node, wanted = job
        page = DownloadParser()
        page.feed(client.get(url, 524288))
        selected = {}
        for link in page.links:
            query = parse_qs(urlsplit(link).query)
            # Select the official IP-based download, never manufacture a port
            # or turn one transport configuration into another.
            if query.get("host") != [node.ip]:
                continue
            proto = "tcp" if query.get("tcp") == ["1"] else "udp"
            if proto in wanted:
                selected[proto] = link
        if not wanted.issubset(selected):
            raise ConversionError("download page lacks the requested IP-based configuration")
        return [replace(node, ovpn=client.get(selected[proto], 262144)) for proto in sorted(wanted)]

    nodes, warnings = [], []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(download, job) for job in jobs]
        for future in as_completed(futures):
            try:
                nodes.extend(future.result())
            except ConversionError as exc:
                warnings.append(str(exc))
    return nodes, warnings, len(index.pages)
