"""Fork tests for the gate flow (piv_gate_bridge.gate).

Runs with the stdlib runner from the repo root:
    python3 -m unittest discover -s tests -t .
Every §6.4 row is driven against a fake card + fake HTTP seam, plus
golden APDU bytes, PIN zeroization, redaction, the stale-GA retry-once,
the §3.10 generation guard, and ordering (GET DATA < challenge < GA).
"""

import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piv_gate_bridge import gate  # noqa: E402
from piv_gate_bridge.gate import (  # noqa: E402
    APDU_GET_DATA_GATE, APDU_SELECT_PIV, CardError,
    Gate, GateHTTP, NoGateCert, RateLimited, StaleResponse,
    TransportError,  # noqa: F401
    Verdict, pad_pin, redact, unwrap_tlv,
)

PIN = bytearray(b"XXXXXX")


def len16(n: int) -> bytes:
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


DER = b"\x30\x82\x01\x22" + b"\x11" * 286   # fake leaf: DER SEQUENCE
SIG71 = b"\x30\x45" + b"\x22" * 69          # 71-byte DER Ecdsa-Sig-Value
SIG72 = b"\x30\x46" + b"\x02\x21\x00" + b"\x22" * 67   # leading-zero INTEGER


def ga_resp(sig: bytes) -> bytes:
    """GA response 7C <len> 82 <len> <DER>, lengths computed (live cards
    emit 71 or 72 B DERs depending on leading-zero INTEGERs)."""
    inner = b"\x82\x82" + len16(len(sig)) + sig
    return b"\x7c\x82" + len16(len(inner)) + inner


class FakeSession:
    """Scripted card: responses consumed in order."""

    def __init__(self, script):
        self.script = list(script)
        self.apdus = []
        self.ended = []             # reset flags passed to end()

    def transmit(self, apdu):
        self.apdus.append(list(apdu))
        data, sw = self.script.pop(0)
        return bytes(data), sw

    def end(self, reset):
        self.ended.append(reset)


class FakeLink:
    def __init__(self, sessions, presence=None, generation=7):
        self.sessions = list(sessions)
        self.presence = list(presence) if presence else None
        self.generation = generation
        self.presence_calls = []

    def wait_for_insertion(self, reader_filter):
        return "Test Reader 00", self.generation

    def still_present(self, reader, generation):
        self.presence_calls.append((reader, generation))
        if generation != self.generation:
            return False
        if self.presence is None:
            return True
        return self.presence.pop(0) if self.presence else False

    def open_session(self, reader):
        return self.sessions.pop(0)


class FakeHTTP:
    def __init__(self, verdicts, challenge_error=None):
        self.verdicts = list(verdicts)
        self.challenge_error = challenge_error
        self.challenges = 0
        self.verifies = 0
        self.received = []

    def challenge(self):
        self.challenges += 1
        if self.challenge_error is not None:
            raise self.challenge_error
        return bytes([self.challenges]) * 32

    def verify(self, nonce, signature, cert):
        self.verifies += 1
        self.received.append((nonce, signature, cert))
        v = self.verdicts.pop(0)
        if isinstance(v, Exception):
            raise v
        return v


class FakeAudit:
    def __init__(self):
        self.events = []

    def log(self, event, **fields):
        self.events.append((event, fields))


def make_prompt(pin=b"XXXXXX"):
    state = {"prompts": 0, "given": []}

    def prompt(attempts_remaining):
        state["prompts"] += 1
        b = bytearray(pin)          # fresh per prompt, like getpass
        state["given"].append(b)
        return b

    return state, prompt


def pass_script():
    """SELECT ok, VERIFY ok, GET DATA (nested 53>70), GA proper."""
    inner70 = b"\x70\x82" + len16(len(DER)) + DER
    resp53 = b"\x53\x82" + len16(len(inner70)) + inner70
    return [
        (b"", 0x9000),                                   # SELECT PIV
        (b"", 0x9000),                                   # VERIFY
        (resp53, 0x9000),                                # GET DATA 5FC105
        (ga_resp(SIG71), 0x9000),                        # GENERAL AUTHENTICATE
    ]


def ga_script(count: int) -> list:
    """pass_script() with `count` GA responses appended after GET DATA
    (§6.4 recovery re-signs without re-running SELECT/PIN)."""
    inner70 = b"\x70\x82" + len16(len(DER)) + DER
    resp53 = b"\x53\x82" + len16(len(inner70)) + inner70
    return [
        (b"", 0x9000),
        (b"", 0x9000),
        (resp53, 0x9000),
    ] + [(ga_resp(SIG71), 0x9000)] * count


def script_with_pin_failures(*pin_sws: int) -> list:
    """pass_script() with extra VERIFY responses inserted before the
    successful one (responses are consumed sequentially)."""
    s = pass_script()
    s[1:1] = [(b"", sw) for sw in pin_sws]
    return s


def run_gate(sessions, verdicts, presence=None, challenge_error=None,
             http=None):
    audit = FakeAudit()
    state, prompt = make_prompt()
    link = FakeLink(sessions, presence=presence)
    http = http or FakeHTTP(verdicts, challenge_error=challenge_error)
    g = Gate(link, http, audit, prompt=prompt)
    return g.run(), audit, state, http, link


class GoldenAPDUs(unittest.TestCase):
    def test_select_piv(self):
        self.assertEqual(
            APDU_SELECT_PIV,
            list(bytes.fromhex("00A404000BA000000308000010000100")))

    def test_verify(self):
        self.assertEqual(
            gate.apdu_verify(pad_pin(b"XXXXXX")),
            [0x00, 0x20, 0x00, 0x80, 0x08,
             0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0xFF, 0xFF])

    def test_pad_pin(self):
        self.assertEqual(pad_pin(b"1234"), b"1234\xff\xff\xff\xff")

    def test_ga(self):
        self.assertEqual(
            gate.apdu_ga(bytes(32)),
            [0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x81, 0x20]
            + [0] * 32 + [0x82, 0x00])
        with self.assertRaises(CardError):
            gate.apdu_ga(bytes(31))

    def test_get_data(self):
        self.assertEqual(
            APDU_GET_DATA_GATE,
            [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05])


class Redaction(unittest.TestCase):
    def test_verify_redacted(self):
        self.assertEqual(redact([0x00, 0x20, 0x00, 0x80, 0x08, 1, 2, 3]),
                         "[VERIFY redacted]")

    def test_ga_redacted(self):
        self.assertEqual(redact(gate.apdu_ga(bytes(32))), "[GA redacted]")

    def test_select_visible(self):
        self.assertEqual(
            redact(APDU_SELECT_PIV),
            "00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00")


class UnwrapTLV(unittest.TestCase):
    def test_bare(self):
        self.assertEqual(unwrap_tlv(DER, (0x53, 0x70)), DER)

    def test_single_53(self):
        self.assertEqual(
            unwrap_tlv(b"\x53\x82" + len16(len(DER)) + DER, (0x53, 0x70)), DER)

    def test_nested_53_70(self):
        inner = b"\x70\x82" + len16(len(DER)) + DER
        wrapped = b"\x53\x82" + len16(len(inner)) + inner
        self.assertEqual(unwrap_tlv(wrapped, (0x53, 0x70)), DER)

    def test_truncated(self):
        with self.assertRaises(CardError):
            unwrap_tlv(b"\x53\x82\x00", (0x53, 0x70))


class HappyPath(unittest.TestCase):
    def test_pass_flow(self):
        result, audit, state, http, link = run_gate(
            [FakeSession(pass_script())], [Verdict("pass")])
        self.assertTrue(result.passed)
        self.assertEqual(result.reader, "Test Reader 00")
        self.assertEqual(result.generation, 7)
        self.assertEqual(http.challenges, 1)
        self.assertEqual(http.verifies, 1)
        # PIN zeroized in place after VERIFY.
        self.assertEqual(list(state["given"][0]), [0] * 6)
        # Audit order: challenge, verify, gate_pass.
        self.assertEqual([e for e, _ in audit.events],
                         ["challenge", "verify", "gate_pass"])
        self.assertEqual(audit.events[0][1]["nonce_hash"],
                         hashlib.sha256(bytes([1]) * 32).hexdigest())
        # APDU order: SELECT < VERIFY < GET DATA < GA; card reset on pass.

    def test_order_and_digest(self):
        session = FakeSession(pass_script())
        result, audit, state, http, _link = run_gate(
            [session], [Verdict("pass")])
        self.assertTrue(result.passed)
        sel, ver, getd, ga = session.apdus
        self.assertEqual(sel, APDU_SELECT_PIV)
        self.assertEqual(ver[:5], [0x00, 0x20, 0x00, 0x80, 0x08])
        self.assertEqual(getd, APDU_GET_DATA_GATE)
        self.assertEqual(ga[:4], [0x00, 0x87, 0x11, 0x9A])
        # GET DATA (index 2) ran before the challenge fetch; GA (index 3)
        # before verify — §3 sequencing.
        self.assertEqual(http.challenges, 1)
        digest = hashlib.sha256(gate.PREFIX + bytes([1]) * 32).digest()
        self.assertEqual(bytes(ga[9:41]), digest)
        # Leaf forwarded untouched (nested 53>70 stripped).
        self.assertEqual(http.received[0][2], DER)
        self.assertEqual(http.received[0][0], bytes([1]) * 32)
        self.assertEqual(http.received[0][1], SIG71)

    def test_session_reset_on_pass(self):
        session = FakeSession(pass_script())
        result, _audit, _state, _http, _link = run_gate(
            [session], [Verdict("pass")])
        self.assertTrue(result.passed)
        self.assertEqual(session.ended, [True])


class GaSign(unittest.TestCase):
    def _run(self, resp, sw=0x9000):
        session = FakeSession([(resp, sw)])
        digest = bytes(32)
        return gate.ga_sign(session, digest), session

    def test_71_byte_sig(self):
        sig, _s = self._run(ga_resp(SIG71))
        self.assertEqual(sig, SIG71)

    def test_72_byte_sig(self):
        # Live regression: 7C 4A 82 48 30 46 02 21 ... — the DER carried a
        # leading-zero INTEGER, so the signature is one byte longer than
        # an earlier hard-coded length.
        sig, _s = self._run(ga_resp(SIG72))
        self.assertEqual(sig, SIG72)

    def test_bad_sw_is_stale(self):
        with self.assertRaises(StaleResponse):
            self._run(ga_resp(SIG71), sw=0x6A82)

    def test_wrong_head_is_stale(self):
        with self.assertRaises(StaleResponse):
            self._run(b"\x44\x71\x01")

    def test_non_der_payload_is_stale(self):
        with self.assertRaises(StaleResponse):
            self._run(ga_resp(b"\x7f" + b"\x00" * 70))


class PinHandling(unittest.TestCase):
    def test_wrong_pin_then_pass(self):
        script = script_with_pin_failures(0x63C2)  # wrong PIN, 2 left
        session = FakeSession(script)
        result, _audit, state, _http, _link = run_gate(
            [session], [Verdict("pass")])
        self.assertTrue(result.passed)
        self.assertEqual(state["prompts"], 2)
        self.assertEqual(list(state["given"][0]), [0] * 6)
        self.assertEqual(list(state["given"][1]), [0] * 6)

    def test_pin_blocked_never_contacts_server(self):
        session = FakeSession(script_with_pin_failures(0x6983))
        result, audit, _state, http, _link = run_gate([session], [])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "pin_blocked")
        self.assertEqual(http.challenges, 0)
        self.assertEqual(audit.events,
                         [("gate_fail", {"reason": "pin_blocked"})])

    def test_pin_zeroized_even_on_failure(self):
        session = FakeSession(script_with_pin_failures(0x63C3))
        _result, _audit, state, _http, _link = run_gate(
            [session], [Verdict("pass")])
        # The gate zeroizes after EVERY VERIFY, success or failure.
        self.assertEqual(list(state["given"][0]), [0] * 6)
        self.assertEqual(list(state["given"][1]), [0] * 6)

    def test_unexpected_verify_sw(self):
        result, _a, _s, http, _l = run_gate(
            [FakeSession(script_with_pin_failures(0x6A80))], [])
        self.assertEqual(result.reason, "pin_verify_failed")
        self.assertEqual(http.challenges, 0)


class ServerVerdicts(unittest.TestCase):
    def test_nonce_unknown_refetch_once(self):
        session = FakeSession(ga_script(2))        # one extra GA for the re-sign
        result, _audit, state, http, _link = run_gate(
            [session],
            [Verdict("fail", "nonce_unknown"), Verdict("pass")])
        self.assertTrue(result.passed)
        self.assertEqual(http.challenges, 2)
        self.assertEqual(http.verifies, 2)
        self.assertEqual(state["prompts"], 1)      # no re-PIN for §6.4 recovery

    def test_nonce_expired_refetch_once(self):
        session = FakeSession(ga_script(2))
        result, _a, _s, http, _l = run_gate(
            [session],
            [Verdict("fail", "nonce_expired"), Verdict("pass")])
        self.assertTrue(result.passed)
        self.assertEqual(http.challenges, 2)
        self.assertEqual(http.verifies, 2)

    def test_nonce_recovery_second_failure_surfaces(self):
        session = FakeSession(ga_script(2))
        result, _a, _s, http, _l = run_gate(
            [session],
            [Verdict("fail", "nonce_unknown"),
             Verdict("fail", "nonce_reused")])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "nonce_reused")

    def test_surface_rows(self):
        # §6.4: every non-recovery fail verdict surfaces immediately —
        # no refetch, no re-sign.
        rows = ["nonce_reused", "nonce_client_mismatch", "bad_cert",
                "not_gate_cert", "bad_chain", "expired_cert", "revoked",
                "bad_signature", "bad_key_type"]
        for reason in rows:
            with self.subTest(reason=reason):
                result, audit, _s, http, _l = run_gate(
                    [FakeSession(pass_script())], [Verdict("fail", reason)])
                self.assertFalse(result.passed)
                self.assertEqual(result.reason, reason)
                self.assertEqual(http.challenges, 1)
                self.assertEqual(http.verifies, 1)
                self.assertEqual(audit.events[-1],
                                 ("gate_fail", {"reason": reason}))

    def test_crl_stale_distinct_message(self):
        result, _a, _s, http, _l = run_gate(
            [FakeSession(pass_script())], [Verdict("fail", "crl_stale")])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "crl_stale")
        self.assertEqual(http.challenges, 1)

    def test_crl_stale_message_is_gate_unavailable(self):
        session = FakeSession(pass_script())
        audit = FakeAudit()
        _state, prompt = make_prompt()
        g = Gate(FakeLink([session]), FakeHTTP([Verdict("fail", "crl_stale")]),
                 audit, prompt=prompt)
        with self.assertLogs("piv-gate", level="ERROR") as cm:
            result = g.run()
        self.assertFalse(result.passed)
        self.assertTrue(any("gate unavailable" in m for m in cm.output))

    def test_replay_nonce_reused_surfaces(self):
        result, _a, _s, http, _l = run_gate(
            [FakeSession(pass_script())], [Verdict("fail", "nonce_reused")])
        self.assertEqual(result.reason, "nonce_reused")
        self.assertEqual(http.verifies, 1)   # surfaced, never resent


class Transport(unittest.TestCase):
    def test_challenge_unreachable(self):
        result, _a, _s, http, _l = run_gate(
            [FakeSession(pass_script())], [],
            challenge_error=TransportError("down"))
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "server_unreachable")
        self.assertEqual(http.verifies, 0)

    def test_verify_ambiguous_never_resent(self):
        # §6.4 ambiguity rule: a transport failure on verify ends the
        # gate — no resend even though the nonce might be reusable.
        result, _a, _s, http, _l = run_gate(
            [FakeSession(pass_script())],
            [TransportError("timeout")])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "server_unreachable")
        self.assertEqual(http.verifies, 1)   # exactly one attempt
        self.assertEqual(http.challenges, 1)

    def test_verify_malformed_200_ends_gate(self):
        result, _a, _s, http, _l = run_gate(
            [FakeSession(pass_script())],
            [TransportError("verify: malformed response")])
        self.assertFalse(result.passed)
        self.assertEqual(http.verifies, 1)


class LifecycleGuards(unittest.TestCase):
    def test_stale_ga_one_full_rerun(self):
        # First session: GA returns a stale/wrong-head response (vpcd
        # quirk).  Second session: everything succeeds — including a
        # fresh PIN prompt and a fresh nonce.
        stale = FakeSession([
            (b"", 0x9000), (b"", 0x9000),
            (b"\x53\x82" + len16(len(DER)) + DER, 0x9000),
            (b"\x44\x71\x01", 0x9000),           # stale response head
        ])
        good = FakeSession(pass_script())
        result, _a, state, http, _l = run_gate([stale, good], [Verdict("pass")])
        self.assertTrue(result.passed)
        self.assertEqual(state["prompts"], 2)    # re-PIN on the fresh session
        self.assertEqual(http.challenges, 2)     # fresh nonce for the re-run
        self.assertEqual(http.verifies, 1)
        self.assertEqual(stale.ended, [False])   # released without reset
        self.assertEqual(good.ended, [True])     # pass path resets

    def test_stale_ga_twice_fails_clean(self):
        sessions = [FakeSession([
            (b"", 0x9000), (b"", 0x9000),
            (b"\x53\x82" + len16(len(DER)) + DER, 0x9000),
            (b"\x44\x71\x01", 0x9000),
        ]) for _ in range(2)]
        result, _a, state, _http, _l = run_gate(sessions, [])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "card_error")
        self.assertEqual(state["prompts"], 2)

    def test_generation_guard_card_removed(self):
        result, audit, _s, _http, link = run_gate(
            [FakeSession(pass_script())], [Verdict("pass")],
            presence=[False])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "card_removed")
        self.assertEqual(audit.events[-1],
                         ("gate_fail", {"reason": "card_removed"}))

    def test_card_removed_after_reset(self):
        # Seated at the §3.10 recheck, gone right after the reset: the
        # session WAS reset, but the pass does not activate.
        session = FakeSession(pass_script())
        result, _a, _s, _http, _l = run_gate(
            [session], [Verdict("pass")], presence=[True, False])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "card_removed")
        self.assertEqual(session.ended, [True])


class NonPIVCard(unittest.TestCase):
    def test_quiet_exit(self):
        session = FakeSession([(b"", 0x6A82)])
        result, audit, _s, http, _l = run_gate([session], [])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "no_piv_applet")
        self.assertEqual(http.challenges, 0)
        self.assertEqual(audit.events, [("gate_fail", {"reason": "no_piv_applet"})])

    def test_fail_carries_reader_and_generation(self):
        # Park decisions need the seated card's identity on the result.
        session = FakeSession([(b"", 0x6A82)])
        result, _a, _s, _http, _l = run_gate([session], [])
        self.assertEqual(result.reader, "Test Reader 00")
        self.assertEqual(result.generation, 7)


class NoGateCert(unittest.TestCase):
    def test_6a82_classified_not_card_error(self):
        # PIV applet with the same PIN but no 5FC105 object (the SSH
        # card): 6A82 is "wrong card", not a generic card error — the
        # bridge parks instead of looping (2026-09-07 pcscd wedge).
        session = FakeSession([
            (b"", 0x9000),      # SELECT PIV (both applets answer)
            (b"", 0x9000),      # VERIFY (same PIN)
            (b"", 0x6A82),      # GET DATA 5FC105: object not found
        ])
        result, audit, _s, http, _l = run_gate([session], [])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "no_gate_cert")
        self.assertEqual(result.reader, "Test Reader 00")
        self.assertEqual(result.generation, 7)
        self.assertEqual(http.challenges, 0)   # never contacts the server
        self.assertEqual(audit.events,
                         [("gate_fail", {"reason": "no_gate_cert"})])

    def test_no_gate_cert_is_card_error_subclass(self):
        # gate.NoGateCert, not this class (same name shadows the import).
        self.assertTrue(issubclass(gate.NoGateCert, CardError))


class RateLimitedHTTP(unittest.TestCase):
    """GateHTTP surfaces HTTP 429 as RateLimited (Retry-After parsed)."""

    @staticmethod
    def _http():
        g = GateHTTP.__new__(GateHTTP)
        g.base = "https://gate.invalid"
        g.timeout = 1.0
        g.retries = 3
        g.backoff = 0.01
        g._ctx = None
        return g

    def test_429_with_retry_after(self):
        import urllib.error
        err = urllib.error.HTTPError(
            "https://gate.invalid/v1/challenge", 429, "Too Many Requests",
            {"Retry-After": "45"}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(RateLimited) as cm:
                self._http()._post("/v1/challenge", b"{}")
        self.assertEqual(cm.exception.retry_after, 45)

    def test_429_without_header(self):
        import urllib.error
        err = urllib.error.HTTPError(
            "https://gate.invalid/v1/challenge", 429, "Too Many Requests",
            {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(RateLimited) as cm:
                self._http()._post("/v1/challenge", b"{}")
        self.assertIsNone(cm.exception.retry_after)

    def test_500_is_plain_transport_error(self):
        import urllib.error
        err = urllib.error.HTTPError(
            "https://gate.invalid/v1/challenge", 500, "boom", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(TransportError) as cm:
                self._http()._post("/v1/challenge", b"{}")
        self.assertNotIsInstance(cm.exception, RateLimited)

    def test_challenge_makes_one_attempt_on_429(self):
        calls = []

        class Counting(GateHTTP):
            def _post(self, path, body):
                calls.append(path)
                raise RateLimited("429")

        g = Counting.__new__(Counting)
        g.base, g.timeout, g.retries, g.backoff, g._ctx = \
            "https://gate.invalid", 1.0, 3, 0.01, None
        with self.assertRaises(RateLimited):
            g.challenge()
        self.assertEqual(len(calls), 1)     # no 3-attempt re-hammer


class RateLimitedResult(unittest.TestCase):
    def test_verify_429_carries_retry_after(self):
        result, _a, _s, http, _l = run_gate(
            [FakeSession(pass_script())],
            [RateLimited("HTTP 429", retry_after=42)])
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "rate_limited")
        self.assertEqual(result.retry_after, 42)
        self.assertEqual(http.verifies, 1)  # surfaced, not resent
        self.assertEqual(http.challenges, 1)


if __name__ == "__main__":
    unittest.main()