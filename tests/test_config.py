"""Fork tests: TOML config (spec §8) parsing."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piv_gate_bridge.config import Config, ConfigError, parse_duration  # noqa: E402

MINIMAL = """
server_url = "https://gate.example.internal"
ca_root = "/etc/piv-gate/step-ca-root.pem"
client_cert = "/etc/piv-gate/machine.crt"
client_key = "/etc/piv-gate/machine.key"
"""


def load(text):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        return Config.load(path)
    finally:
        os.unlink(path)


class ConfigTests(unittest.TestCase):
    def test_minimal_gets_spec_defaults(self):
        cfg = load(MINIMAL)
        self.assertEqual(cfg.t_idle, 600.0)      # 10m
        self.assertEqual(cfg.t_max, 43200.0)     # 12h
        self.assertEqual(cfg.http_timeout, 10.0)
        self.assertEqual(cfg.retries, 3)
        self.assertIsNone(cfg.reader_filter)

    def test_full_spec8_shape(self):
        cfg = load(MINIMAL + """
t_idle = "10m"
t_max = "12h"
http_timeout = "10s"
retries = 3
reader_filter = "Identiv"
audit_log = "~/.local/state/piv-gate/audit.jsonl"
""")
        self.assertEqual(cfg.reader_filter, "Identiv")
        self.assertEqual(cfg.audit_log, "~/.local/state/piv-gate/audit.jsonl")

    def test_missing_required_key(self):
        with self.assertRaises(ConfigError):
            load('server_url = "https://x"\n')

    def test_unknown_key_rejected(self):
        with self.assertRaises(ConfigError):
            load(MINIMAL + 'extra = 1\n')

    def test_durations(self):
        self.assertEqual(parse_duration("10m"), 600.0)
        self.assertEqual(parse_duration("12h"), 43200.0)
        self.assertEqual(parse_duration("10s"), 10.0)
        self.assertEqual(parse_duration("250ms"), 0.25)
        with self.assertRaises(ConfigError):
            parse_duration("10x")
        with self.assertRaises(ConfigError):
            parse_duration("0m")


if __name__ == "__main__":
    unittest.main()