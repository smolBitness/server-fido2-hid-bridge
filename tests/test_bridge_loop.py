"""Bridge main-loop fail classification (piv_gate_bridge.bridge.Bridge.run).

A failed GateResult must NOT re-gate instantly (the 2026-09-07 failure
mode: wrong card + 429 hammered pcscd and the server).  Scripted
run_gate results + recorded sleeps:

  * park reasons  -> _park, no timed sleep, wakes on generation change
  * rate_limited  -> sleeps max(retry_after|30, 30) capped at 300
  * other reasons -> exponential 1s -> 60s
  * a pass resets the escalation

asyncio.sleep is replaced with a recorder that raises StopLoop when the
planned sleep budget is exhausted, so the loop terminates deterministically.
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piv_gate_bridge import bridge as bridge_mod  # noqa: E402
from piv_gate_bridge.bridge import Bridge  # noqa: E402
from piv_gate_bridge.gate import GateResult  # noqa: E402


class StopLoop(Exception):
    pass


class _Exhausted(Exception):
    pass


class FakeAudit:
    def __init__(self):
        self.events = []

    def log(self, event, **fields):
        self.events.append((event, fields))


class FakeParkLink:
    def __init__(self):
        self.calls = []

    def wait_for_generation_change(self, reader, generation):
        self.calls.append((reader, generation))


class FakeTransport:
    def __init__(self, *args, **kwargs):
        pass

    def close(self):
        pass


class FakeDev:
    def __init__(self, transport=None):
        self.transport = transport

    async def start(self):
        pass

    def destroy(self):
        pass


def make_bridge(results):
    b = Bridge.__new__(Bridge)
    b.audit = FakeAudit()
    b._gate_link = None          # run_gate assigns a fresh link per run
    b._signal_exit = False
    b.session = None
    b.server_url = "https://gate.invalid"
    b.ca_root = "/dev/null"
    b.client_cert = "/dev/null"
    b.client_key = "/dev/null"
    b.http_timeout = 1.0
    script = iter(results)
    park_calls = []

    def run_gate():
        try:
            r = next(script)
        except StopIteration:
            raise _Exhausted() from None
        link = FakeParkLink()
        link.calls = park_calls          # shared recording across runs
        b._gate_link = link              # like CardLink() per gate run
        return r

    b.run_gate = run_gate
    b._park_calls = park_calls       # shared recording across every park
    return b


async def drive(test, b, expected_sleeps):
    """Run Bridge.run() until one more sleep than expected happens."""
    calls = []

    async def fake_sleep(delay, *args, **kwargs):
        if len(calls) >= len(expected_sleeps):
            raise StopLoop
        calls.append(delay)

    async def fake_live_phase(self, result, dev):
        return "error"

    with mock.patch.object(bridge_mod.asyncio, "sleep", fake_sleep), \
            mock.patch.object(Bridge, "install_signal_handlers",
                              lambda self, loop: None), \
            mock.patch.object(Bridge, "live_phase_async", fake_live_phase), \
            mock.patch.object(bridge_mod, "HttpCtapTransport", FakeTransport), \
            mock.patch.object(bridge_mod, "CTAPHIDDevice", FakeDev):
        try:
            await b.run()
        except StopLoop:
            pass
        else:
            test.fail("bridge loop outlived its sleep budget")
    return calls


class Park(unittest.TestCase):
    def test_wrong_card_reasons_park_without_sleep(self):
        results = [
            GateResult(False, "no_gate_cert", "RDR", 7),
            GateResult(False, "no_piv_applet", "RDR", 8),
            GateResult(False, "pin_blocked", "RDR", 9),
            GateResult(False, "revoked"),        # consumes a backoff sleep
        ]
        b = make_bridge(results)
        calls = asyncio.run(drive(self, b, [1.0]))
        self.assertEqual(calls, [1.0])          # parks consumed no sleeps
        self.assertEqual(b._park_calls,
                         [("RDR", 7), ("RDR", 8), ("RDR", 9)])

    def test_park_is_audited_and_clears_the_gate_link(self):
        results = [GateResult(False, "no_gate_cert", "RDR", 7),
                   GateResult(False, "revoked")]
        b = make_bridge(results)
        asyncio.run(drive(self, b, [1.0]))
        park_events = [e for e, _ in b.audit.events if e == "gate_park"]
        unpark_events = [e for e, _ in b.audit.events if e == "gate_unpark"]
        self.assertEqual(park_events, ["gate_park"])
        self.assertEqual(unpark_events, ["gate_unpark"])
        self.assertIsNotNone(b._gate_link)   # refreshed by the next run


class RateLimited(unittest.TestCase):
    def test_retry_after_honored(self):
        results = [GateResult(False, "rate_limited", "RDR", 7, retry_after=45),
                   GateResult(False, "revoked")]
        b = make_bridge(results)
        calls = asyncio.run(drive(self, b, [45.0]))
        self.assertEqual(calls, [45.0])

    def test_floor_30_when_no_hint(self):
        results = [GateResult(False, "rate_limited", "RDR", 7,
                              retry_after=None),
                   GateResult(False, "revoked")]
        b = make_bridge(results)
        calls = asyncio.run(drive(self, b, [30.0]))
        self.assertEqual(calls, [30.0])

    def test_cap_300(self):
        results = [GateResult(False, "rate_limited", "RDR", 7,
                              retry_after=900),
                   GateResult(False, "revoked")]
        b = make_bridge(results)
        calls = asyncio.run(drive(self, b, [300.0]))
        self.assertEqual(calls, [300.0])


class Escalation(unittest.TestCase):
    def test_other_reasons_escalate_1_2_4(self):
        results = [GateResult(False, "revoked") for _ in range(3)]
        b = make_bridge(results)
        calls = asyncio.run(drive(self, b, [1.0, 2.0, 4.0]))
        self.assertEqual(calls, [1.0, 2.0, 4.0])

    def test_pass_resets_escalation(self):
        results = [
            GateResult(False, "revoked"),
            GateResult(False, "revoked"),
            GateResult(True, None, "stub", 0),   # pass -> live phase
            GateResult(False, "revoked"),
        ]
        b = make_bridge(results)
        calls = asyncio.run(drive(self, b, [1.0, 2.0, 1.0]))
        self.assertEqual(calls, [1.0, 2.0, 1.0])


class TotpPath(unittest.TestCase):
    """A pass with result.want (TOTP picker choice): no UHID device —
    the code is fetched, shown as a notification, and the bridge parks
    until the card is swapped."""

    def make(self, results, totp):
        b = make_bridge(results)
        b._gate_http = mock.Mock(totp=mock.Mock(side_effect=totp))
        return b

    def _drive(self, b):
        created = []

        async def fake_sleep(delay, *args, **kwargs):
            raise StopLoop

        async def fake_live(self, result, dev):
            created.append(result)

        with mock.patch.object(bridge_mod.asyncio, "sleep", fake_sleep), \
                mock.patch.object(Bridge, "install_signal_handlers",
                                  lambda self, loop: None), \
                mock.patch.object(Bridge, "live_phase_async", fake_live), \
                mock.patch.object(bridge_mod, "HttpCtapTransport",
                                  FakeTransport), \
                mock.patch.object(bridge_mod, "CTAPHIDDevice", FakeDev), \
                mock.patch.object(bridge_mod, "notify_info") as fake_info:
            try:
                asyncio.run(b.run())
            except StopLoop:
                pass
        return created, fake_info

    def test_want_pass_shows_code_and_parks_without_a_device(self):
        results = [GateResult(True, None, "RDR", 7, want="example"),
                   GateResult(False, "revoked")]
        b = self.make(results, totp=[("654321", "2026-09-07T12:00:00Z")])
        created, fake_info = self._drive(b)
        self.assertEqual(created, [])           # no UHID device, ever
        self.assertEqual(b._park_calls, [("RDR", 7)])
        fake_info.assert_called_once()
        self.assertEqual(fake_info.call_args[0][0], "TOTP example")
        self.assertIn("654321", fake_info.call_args[0][1])
        events = [e for e, _ in b.audit.events]
        self.assertIn("totp_shown", events)
        self.assertIn("gate_unpark", events)
        # The code itself is never written to the audit log.
        for _, fields in b.audit.events:
            self.assertNotIn("654321", str(fields))

    def test_totp_failure_still_parks_without_a_device(self):
        results = [GateResult(True, None, "RDR", 7, want="example"),
                   GateResult(False, "revoked")]
        b = self.make(results, totp=[RuntimeError("totp refused: epoch_closed")])
        created, fake_info = self._drive(b)
        self.assertEqual(created, [])
        self.assertEqual(b._park_calls, [("RDR", 7)])   # parks anyway
        # The refusal is surfaced on screen, not just logged.
        fake_info.assert_called_once()
        self.assertIn("epoch_closed", fake_info.call_args[0][1])
        self.assertNotIn("totp_shown", [e for e, _ in b.audit.events])


if __name__ == "__main__":
    unittest.main()