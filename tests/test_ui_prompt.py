"""Applet-picker tests: the arbiter seam (Gate), the notification seam
(ui), and the bridge loop's user_ssh park + SCD LEARN handoff.

Dual-applet cards get one notify-send popup; gate / timeout proceed with
the ceremony, ssh / dismiss park until the card is swapped.  PIV-only
cards and missing UI never block the gate.
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piv_gate_bridge import bridge as bridge_mod  # noqa: E402
from piv_gate_bridge import ui  # noqa: E402
from piv_gate_bridge.bridge import Bridge  # noqa: E402
from piv_gate_bridge.gate import Gate, GateResult, Verdict  # noqa: E402

from tests.test_bridge_loop import drive, make_bridge  # noqa: E402
from tests.test_gate import (  # noqa: E402
    FakeAudit, FakeHTTP, FakeLink, FakeSession, make_prompt, pass_script,
)


class ProbeLink(FakeLink):
    """FakeLink + an applet probe answer."""

    def __init__(self, sessions, kind=None):
        super().__init__(sessions)
        self.kind = kind
        self.probed = []

    def probe_applets(self, reader):
        self.probed.append(reader)
        return self.kind


def make_gate(sessions, verdicts, kind, choice, ask_calls,
              totp_labels=None):
    audit = FakeAudit()
    _state, prompt = make_prompt()

    def ui_ask(title, body, actions, timeout_s, reader=None, generation=None):
        ask_calls.append((title, actions, timeout_s))
        return choice

    link = ProbeLink(sessions, kind=kind)
    http = FakeHTTP(verdicts)
    g = Gate(link, http, audit, prompt=prompt, ui_ask=ui_ask,
             ui_timeout=20.0, totp_labels=totp_labels)
    return g.run(), audit, link, http


class GateArbiter(unittest.TestCase):
    def test_ssh_choice_parks_without_touching_the_card(self):
        ask_calls = []
        link = ProbeLink([], kind="dual")
        result, audit, link, http = make_gate(
            [], [], "dual", "ssh", ask_calls)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "user_ssh")
        self.assertEqual(result.reader, "Test Reader 00")
        self.assertEqual(link.sessions, [])     # no session opened
        self.assertEqual(http.challenges, 0)    # no server contact
        choices = [f for e, f in audit.events if e == "applet_choice"]
        self.assertEqual(choices, [{"choice": "ssh",
                                    "reader": "Test Reader 00",
                                    "generation": 7}])
        self.assertEqual(ask_calls[0][2], 20.0)  # timeout passed through

    def test_gate_choice_runs_the_ceremony(self):
        result, audit, link, http = make_gate(
            [FakeSession(pass_script())], [Verdict("pass")],
            "dual", "gate", [])
        self.assertTrue(result.passed)

    def test_timeout_defaults_to_gate(self):
        result, audit, link, http = make_gate(
            [FakeSession(pass_script())], [Verdict("pass")],
            "dual", None, [])
        self.assertTrue(result.passed)

    def test_dismiss_parks(self):
        result, audit, link, http = make_gate(
            [], [], "dual", "dismiss", [])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "user_dismissed")

    def test_piv_only_card_never_prompts(self):
        ask_calls = []
        result, audit, link, http = make_gate(
            [FakeSession([(b"", 0x6A82)])], [], "piv", "unused", ask_calls)
        self.assertEqual(ask_calls, [])         # no popup
        self.assertEqual(result.reason, "no_piv_applet")

    def test_probe_unreadable_card_never_prompts(self):
        ask_calls = []
        result, audit, link, http = make_gate(
            [FakeSession([(b"", 0x6A82)])], [], None, "unused", ask_calls)
        self.assertEqual(ask_calls, [])
        self.assertEqual(result.reason, "no_piv_applet")

    def test_piv_only_card_prompts_when_totp_labels_configured(self):
        ask_calls = []
        result, audit, link, http = make_gate(
            [FakeSession(pass_script())], [Verdict("pass")],
            "piv", "totp:example", ask_calls, totp_labels=["example"])
        # PIV-only card: Gate / TOTP / Not now (no SSH action).
        self.assertEqual(ask_calls[0][1],
                         {"gate": "Gate (passkey)", "totp:example":
                          "TOTP: example", "dismiss": "Not now"})
        self.assertTrue(result.passed)
        self.assertEqual(result.want, "example")

    def test_dual_card_with_totp_labels_gets_all_four_actions(self):
        ask_calls = []
        result, audit, link, http = make_gate(
            [FakeSession(pass_script())], [Verdict("pass")],
            "dual", "gate", ask_calls, totp_labels=["example"])
        self.assertEqual(set(ask_calls[0][1]),
                         {"gate", "ssh", "totp:example", "dismiss"})
        self.assertTrue(result.passed)
        self.assertIsNone(result.want)      # plain gate choice

    def test_no_labels_keeps_piv_only_cards_silent(self):
        ask_calls = []
        result, audit, link, http = make_gate(
            [FakeSession([(b"", 0x6A82)])], [], "piv", "unused",
            ask_calls, totp_labels=[])
        self.assertEqual(ask_calls, [])     # no popup
        self.assertEqual(result.reason, "no_piv_applet")

    def test_no_ui_skips_the_probe_entirely(self):
        link = ProbeLink([FakeSession([(b"", 0x6A82)])], kind="dual")
        link.probed.append("sentinel")
        audit = FakeAudit()
        g = Gate(link, FakeHTTP([]), audit)     # no ui_ask
        result = g.run()
        self.assertEqual(link.probed, ["sentinel"])  # run() didn't probe
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "no_piv_applet")


class CachedAsk(unittest.TestCase):
    """Bridge._cached_ask: one popup per seated card, and a gate-default
    choice reclaims the reader from scdaemon."""

    def make(self, choice):
        b = Bridge.__new__(Bridge)
        b.audit = FakeAudit()
        b.ui_ask = mock.Mock(return_value=choice)
        b._ask_cache = (None, None)
        return b

    def test_asked_once_per_generation(self):
        b = self.make("ssh")
        kw = dict(reader="RDR", generation=7)
        self.assertEqual(b._cached_ask("t", "b", {"ssh": "SSH"}, 20.0, **kw),
                         "ssh")
        self.assertEqual(b._cached_ask("t", "b", {"ssh": "SSH"}, 20.0, **kw),
                         "ssh")
        b.ui_ask.assert_called_once()

    def test_new_generation_asks_again(self):
        b = self.make("ssh")
        with mock.patch.object(bridge_mod.subprocess, "run"):
            b._cached_ask("t", "b", {}, 20.0, reader="RDR", generation=7)
            b._cached_ask("t", "b", {}, 20.0, reader="RDR", generation=8)
        self.assertEqual(b.ui_ask.call_count, 2)

    def test_gate_default_kills_scdaemon(self):
        b = self.make(None)
        with mock.patch.object(bridge_mod.subprocess, "run") as m:
            b._cached_ask("t", "b", {"gate": "G"}, 20.0,
                          reader="RDR", generation=7)
        self.assertEqual(m.call_args[0][0],
                         ["gpgconf", "--kill", "scdaemon"])

    def test_totp_choice_kills_scdaemon(self):
        # totp:<label> continues into the PIV ceremony, which needs the
        # reader back from scdaemon just like a gate choice.
        b = self.make("totp:example")
        with mock.patch.object(bridge_mod.subprocess, "run") as m:
            b._cached_ask("t", "b", {"totp:example": "TOTP"}, 20.0,
                          reader="RDR", generation=7)
        self.assertEqual(m.call_args[0][0],
                         ["gpgconf", "--kill", "scdaemon"])

    def test_ssh_choice_leaves_scdaemon_alone(self):
        b = self.make("ssh")
        with mock.patch.object(bridge_mod.subprocess, "run") as m:
            b._cached_ask("t", "b", {"gate": "G"}, 20.0,
                          reader="RDR", generation=7)
        m.assert_not_called()


class NotifySeam(unittest.TestCase):
    def test_ask_gdbus_choice_wins(self):
        with mock.patch.object(ui, "_gdbus_ask", return_value="ssh"):
            self.assertEqual(
                ui.notify_ask("T", "B", {"gate": "Gate", "ssh": "SSH"},
                              20.0), "ssh")

    def test_ask_gdbus_failure_falls_back_to_notify_send(self):
        proc = mock.Mock(returncode=0, stdout="ssh\n")
        with mock.patch.object(ui, "_gdbus_ask",
                               side_effect=OSError("no gio")), \
                mock.patch.object(ui.subprocess, "run",
                                  return_value=proc) as m:
            choice = ui.notify_ask("T", "B", {"gate": "Gate", "ssh": "SSH"},
                                   20.0)
        self.assertEqual(choice, "ssh")
        argv = m.call_args[0][0]
        self.assertEqual(argv[0], "notify-send")
        self.assertIn("--expire-time=20000", argv)
        self.assertIn("--action=gate=Gate", argv)
        self.assertIn("--action=ssh=SSH", argv)

    def test_ask_silent_desktop_returns_none(self):
        proc = mock.Mock(returncode=0, stdout="")
        with mock.patch.object(ui, "_gdbus_ask",
                               side_effect=OSError("no bus")), \
                mock.patch.object(ui.subprocess, "run", return_value=proc):
            self.assertIsNone(ui.notify_ask("T", "B", {"a": "A"}, 5.0))

    def test_ask_failure_returns_none(self):
        with mock.patch.object(ui, "_gdbus_ask",
                               side_effect=OSError("no bus")), \
                mock.patch.object(ui.subprocess, "run",
                                  side_effect=OSError("no notify")):
            self.assertIsNone(ui.notify_ask("T", "B", {"a": "A"}, 5.0))


class BridgeLoopHandoff(unittest.TestCase):
    def test_user_ssh_parks_and_runs_scd_learn(self):
        results = [GateResult(False, "user_ssh", "RDR", 7),
                   GateResult(False, "revoked")]
        b = make_bridge(results)
        learned = []

        def fake_run(argv, **kwargs):
            learned.append(argv)
            return mock.Mock(returncode=0)

        with mock.patch.object(bridge_mod, "subprocess") as fake_sub, \
                mock.patch.object(bridge_mod, "notify_info") as fake_info:
            fake_sub.run.side_effect = fake_run
            calls = asyncio.run(drive(self, b, []))
        self.assertEqual(calls, [])             # park consumed no sleeps
        self.assertEqual(learned,
                         [["gpg-connect-agent", "SCD LEARN --force", "/bye"]])
        fake_info.assert_called_once()
        self.assertIn(("RDR", 7), b._park_calls)

    def test_user_dismissed_parks_without_handoff(self):
        results = [GateResult(False, "user_dismissed", "RDR", 7),
                   GateResult(False, "revoked")]
        b = make_bridge(results)
        with mock.patch.object(bridge_mod, "subprocess") as fake_sub, \
                mock.patch.object(bridge_mod, "notify_info") as fake_info:
            calls = asyncio.run(drive(self, b, []))
        self.assertEqual(calls, [])
        fake_sub.run.assert_not_called()
        fake_info.assert_not_called()
        self.assertIn(("RDR", 7), b._park_calls)


if __name__ == "__main__":
    unittest.main()