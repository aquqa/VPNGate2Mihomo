from dataclasses import dataclass, field
from typing import Any


class ConversionError(ValueError):
    """A safe-to-log error which never contains source configuration material."""


@dataclass
class SourceNode:
    hostname: str
    ip: str
    country: str = "ZZ"
    country_name: str = "Unknown"
    score: int = 0
    speed: int = 0
    ping: int | None = None
    ovpn: str = field(default="", repr=False)


@dataclass
class Candidate:
    source: SourceNode
    proxy: dict[str, Any] = field(repr=False)

    @property
    def endpoint(self) -> tuple[str, int, str]:
        return self.proxy["server"], self.proxy["port"], self.proxy["proto"]
