"""Bridge configuration (spec v1.1 §8, shape normative).  tomllib."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Optional

DEFAULTS = {
    "t_idle": "10m",         # CTAPHID inactivity -> teardown
    "t_max": "12h",          # absolute ceiling since gate pass
    "http_timeout": "10s",   # per request
    "retries": 3,            # challenge fetch / network errors (§6.4)
    "reader_filter": None,   # substring match on PC/SC reader name
    "audit_log": "~/.local/state/piv-gate/audit.jsonl",
}

REQUIRED = ("server_url", "ca_root", "client_cert", "client_key")


class ConfigError(Exception):
    pass


def parse_duration(s: str) -> float:
    """'10m' / '12h' / '10s' / '250ms' -> seconds."""
    units = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    s = s.strip()
    for suffix in ("ms", "m", "h", "s"):        # ms before m/s
        if s.endswith(suffix):
            try:
                value = float(s[: -len(suffix)])
            except ValueError:
                break
            seconds = value * units[suffix]
            if seconds <= 0:
                raise ConfigError(f"non-positive duration: {s}")
            return seconds
    raise ConfigError(f"invalid duration: {s!r}")


class Config:
    """Spec §8 keys, exactly."""

    def __init__(self, doc: dict) -> None:
        missing = [k for k in REQUIRED if k not in doc]
        if missing:
            raise ConfigError(f"missing config keys: {', '.join(missing)}")
        unknown = set(doc) - set(REQUIRED) - set(DEFAULTS)
        if unknown:
            raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")
        self.server_url: str = doc["server_url"]
        self.ca_root: str = doc["ca_root"]
        self.client_cert: str = doc["client_cert"]
        self.client_key: str = doc["client_key"]
        self.t_idle: float = parse_duration(doc.get("t_idle", DEFAULTS["t_idle"]))
        self.t_max: float = parse_duration(doc.get("t_max", DEFAULTS["t_max"]))
        self.http_timeout: float = parse_duration(
            doc.get("http_timeout", DEFAULTS["http_timeout"]))
        self.retries: int = int(doc.get("retries", DEFAULTS["retries"]))
        self.reader_filter: Optional[str] = doc.get("reader_filter",
                                                    DEFAULTS["reader_filter"])
        self.audit_log: str = doc.get("audit_log", DEFAULTS["audit_log"])

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path, "rb") as f:
            return cls(tomllib.load(f))