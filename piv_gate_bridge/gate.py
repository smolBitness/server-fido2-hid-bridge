"""PIV gate flow — bridge spec v1.1 §2/§3 (normative).

One seat session = one card insertion -> one PIN prompt -> one gate round
trip -> live device.  Invariants enforced in this module:

  * the server is never contacted before the PIN is verified (§3);
  * PIN failures never touch the network (§3.5);
  * the PIN is zeroized immediately after VERIFY (§3.5);
  * VERIFY / GENERAL AUTHENTICATE APDUs are never logged (§10);
  * a verify transport failure ends the gate — never a blind resend (§6.4);
  * the pass authorizes this insertion only (generation recheck, §3.10);
  * after a pass the card is reset before the relay phase (§2 hygiene).

The card seams (CardLink / CardSession) and the HTTP seam (GateHTTP)
exist so tests can drive every §6.4 row with fake card + fake server.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional, Sequence

log = logging.getLogger("piv-gate")

PREFIX = b"piv-fido-gate-v1"
PIV_AID = bytes.fromhex("A000000308000010000100")
# OpenPGP RID+application prefix (generic, no card serial): a shared
# SELECT answers 9000 on SmartPGP cards (verified live 2026-09-08), so
# the dual-applet probe needs no per-card AID.
OPENPGP_AID_PREFIX = bytes.fromhex("D27600012401")

SW_OK = 0x9000
SW_PIN_BLOCKED = 0x6983

# APDU templates (§4).  SELECT PIV carries no Le; GET DATA Lc=5 for the
# single tag 5C 03 5F C1 05.
APDU_SELECT_PIV = [0x00, 0xA4, 0x04, 0x00, 0x0B] + list(PIV_AID)
APDU_GET_DATA_GATE = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05]

# GENERAL AUTHENTICATE, P1=0x11 (ECC P-256), P2=9A (SP 800-78-5 Tbl 9):
# 7C 24 81 20 <32B digest> 82 00 — Lc 0x26.  Response is
# 7C <len> 82 <len> <DER>; the DER signature is 70-72 B (leading-zero
# INTEGERs vary), so lengths are parsed, never assumed.

PUK_MESSAGE = (
    "PIN is blocked (attempts exhausted).  Unblock with the PUK "
    "(PIV RESET RETRY COUNTER), then reinsert the card."
)


class CardError(Exception):
    """Card/session-level failure (connect, transmit, unexpected SW)."""


class StaleResponse(CardError):
    """Malformed card response to GENERAL AUTHENTICATE.

    The vpcd relay serves one stale response on the first session after
    card registration; the bridge answers with exactly one full re-run
    on a fresh session, including a fresh PIN prompt."""


class TransportError(Exception):
    """Network failure — distinct from a server verdict (§6.3)."""


class RateLimited(TransportError):
    """HTTP 429 from the server.  Distinct from a plain transport
    failure: the bridge must back off (Retry-After when given), not
    re-gate immediately — a fast loop both sustains the limit and
    churns pcscd (2026-09-07)."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


class NoGateCert(CardError):
    """The seated PIV card has no 5FC105 gate-cert object (6A82).

    A PIV applet with the same PIN but no gate credential is the
    wrong-card case (e.g. the SSH card): park instead of looping."""


@dataclass
class Verdict:
    result: str                     # "pass" | "fail"
    reason: Optional[str] = None


@dataclass
class GateResult:
    passed: bool
    reason: Optional[str] = None    # local fail reason when passed=False
    reader: Optional[str] = None
    generation: Optional[int] = None
    retry_after: Optional[int] = None   # rate_limited: server hint (s)
    want: Optional[str] = None      # totp picker choice: fetch a code


# --- helpers ---------------------------------------------------------------

def redact(apdu: Sequence[int]) -> str:
    """Render an APDU for debug logs.  VERIFY (INS 0x20) and GENERAL
    AUTHENTICATE (INS 0x87) bodies carry the PIN / the digest and are
    never logged (§10)."""
    if len(apdu) >= 2:
        if apdu[1] == 0x20:
            return "[VERIFY redacted]"
        if apdu[1] == 0x87:
            return "[GA redacted]"
    return " ".join(f"{b:02X}" for b in apdu)


def pad_pin(pin: bytes) -> bytes:
    """PIV VERIFY pads the PIN with 0xFF to 8 bytes (§3.5)."""
    return pin + b"\xff" * (8 - len(pin))


def apdu_verify(pin_padded: Sequence[int]) -> list:
    return [0x00, 0x20, 0x00, 0x80, 0x08] + list(pin_padded)


def apdu_ga(digest: bytes) -> list:
    if len(digest) != 32:
        raise CardError("GA digest must be 32 bytes")
    return [0x00, 0x87, 0x11, 0x9A, 0x26,
            0x7C, 0x24, 0x81, 0x20] + list(digest) + [0x82, 0x00]


def unwrap_tlv(blob: bytes, wrapper_tags: Sequence[int]) -> bytes:
    """Strip nested TLV wrappers (53/70, §3.6) down to the leaf value."""
    while len(blob) >= 2 and blob[0] in wrapper_tags:
        length_byte = blob[1]
        if length_byte < 0x80:
            head, length = 2, length_byte
        else:
            n = length_byte & 0x7F
            if n == 0 or n > 2 or len(blob) < 2 + n:
                raise CardError(f"unsupported TLV length 0x{length_byte:02X}")
            head = 2 + n
            length = int.from_bytes(blob[2:head], "big")
        if len(blob) < head + length:
            raise CardError("truncated TLV")
        blob = blob[head:head + length]
    return blob


# --- audit (§9) --------------------------------------------------------------

class Audit:
    """Bridge-local JSONL, append-only, fsync per line."""

    def __init__(self, path: str) -> None:
        self.path = os.path.expanduser(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._f = open(self.path, "a", encoding="utf-8")

    def log(self, event: str, **fields: object) -> None:
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
               "event": event}
        rec.update(fields)
        try:
            self._f.write(json.dumps(rec, sort_keys=True) + "\n")
            self._f.flush()
            os.fsync(self._f.fileno())
        except OSError:
            # Local-only in v1 (§9): the server keeps the authoritative
            # log; a dead audit sink must not break authentication.
            pass

    def close(self) -> None:
        try:
            self._f.close()
        except OSError:
            pass


# --- card seams --------------------------------------------------------------

class CardLink:
    """PC/SC insertion detection + session factory (§3.1, §3.10)."""

    def __init__(self) -> None:
        from smartcard.scard import SCARD_SCOPE_USER, SCardEstablishContext
        hresult, self._ctx = SCardEstablishContext(SCARD_SCOPE_USER)
        if hresult != 0:
            raise CardError(f"SCardEstablishContext: 0x{hresult:08X}")

    def _readers(self) -> list:
        from smartcard.scard import SCardListReaders
        hresult, names = SCardListReaders(self._ctx, [])
        if hresult != 0:
            return []               # no readers right now — hotplug-safe
        return list(names)

    def wait_for_insertion(self, reader_filter: Optional[str]) -> tuple:
        """Block until a card is present; return (reader, generation).

        generation = dwEventState >> 16 (PC/SC insertion counter); a
        remove+reinsert bumps it, which the §3.10 recheck detects.
        reader_filter is a substring match on the reader name.
        """
        from smartcard.scard import (
            INFINITE, SCARD_STATE_PRESENT, SCARD_STATE_UNAWARE,
            SCardGetStatusChange,
        )
        while True:
            names = [r for r in self._readers()
                     if not reader_filter or reader_filter in r]
            if not names:
                time.sleep(1.0)
                continue
            states = [(n, SCARD_STATE_UNAWARE) for n in names]
            hresult, newstates = SCardGetStatusChange(self._ctx, INFINITE, states)
            if hresult != 0:        # pcscd restart / context hiccup
                time.sleep(1.0)
                continue
            for name, eventstate, _atr in newstates:
                if eventstate & SCARD_STATE_PRESENT:
                    return name, eventstate >> 16

    def still_present(self, reader: str, generation: int) -> bool:
        """§3.10 recheck: present AND insertion generation unchanged."""
        from smartcard.scard import (
            SCARD_STATE_PRESENT, SCARD_STATE_UNAWARE, SCardGetStatusChange,
        )
        hresult, newstates = SCardGetStatusChange(
            self._ctx, 0, [(reader, SCARD_STATE_UNAWARE)])
        if hresult != 0:
            return False            # fail closed: unqueryable == absent
        for name, eventstate, _atr in newstates:
            if name == reader:
                return (bool(eventstate & SCARD_STATE_PRESENT)
                        and eventstate >> 16 == generation)
        return False

    def wait_for_generation_change(self, reader: str, generation: int,
                                   tick_s: float = 1.0) -> bool:
        """Block (polling, no INFINITE waits) until the seated card is
        swapped: a remove+reinsertion bumps the PC/SC insertion counter
        past `generation`.  Used to PARK on a wrong-card / blocked-PIN
        failure instead of looping timed retries (2026-09-07: a ~1.5 s
        loop churned pcscd contexts into a system-wide wedge).

        Returns True when a different card generation is present or the
        reader went absent and stayed absent; False when the context is
        dead (pcscd restart) — the caller then re-enters the normal
        gate run with a fresh CardLink."""
        from smartcard.scard import (
            SCARD_STATE_PRESENT, SCARD_STATE_UNAWARE, SCardGetStatusChange,
        )
        absent_ticks = 0
        while True:
            time.sleep(tick_s)
            names = self._readers()
            if reader not in names:
                absent_ticks += 1
                if absent_ticks >= 2:
                    return True     # reader gone; next run re-discovers
                continue
            absent_ticks = 0
            hresult, newstates = SCardGetStatusChange(
                self._ctx, 0, [(reader, SCARD_STATE_UNAWARE)])
            if hresult != 0:
                return False        # context dead: fresh run recovers
            for name, eventstate, _atr in newstates:
                if name == reader:
                    if (eventstate & SCARD_STATE_PRESENT
                            and eventstate >> 16 > generation):
                        return True

    def probe_alive(self, reader: str) -> bool:
        """§3.10 liveness probe: SELECT PIV must answer 9000.

        vpcd keeps SCARD_STATE_PRESENT asserted as long as the phone app
        holds the reader socket — even with the card lifted — so the
        presence bit alone is not a removal signal on the relay.  A live
        card answers the SELECT; garbage SW (e.g. 6F00/4471), a transport
        exception, or a hang all mean the card is not reachable.  Callers
        bound this with a timeout and require consecutive failures."""
        from smartcard.scard import SCARD_SHARE_SHARED
        from smartcard.System import readers as system_readers
        try:
            matches = [r for r in system_readers() if str(r) == reader]
            if not matches:
                return False
            conn = matches[0].createConnection()
            conn.connect(protocol=SCARD_SHARE_SHARED)
            try:
                resp, sw1, sw2 = conn.transmit(list(APDU_SELECT_PIV))
                return sw1 << 8 | sw2 == SW_OK
            finally:
                conn.disconnect()
        except Exception:
            return False

    def probe_applets(self, reader: str) -> Optional[str]:
        """Best-effort applet classification BEFORE the ceremony, over a
        SHARED connection (no PIN, no transaction): 'dual' = both the PIV
        and the OpenPGP applet answer SELECT, 'piv' = PIV only, None =
        unprobeable (reader vanished, connect or transmit failed) — the
        normal ceremony then delivers the authoritative verdict.

        The card is talking T=1 over the SCR3310; connecting without a
        protocol request lets pcscd negotiate and pyscard transmits with
        the negotiated one (forcing T0 on a T1 card raises
        0x8010000F protocol mismatch)."""
        from smartcard.System import readers as system_readers
        try:
            matches = [r for r in system_readers() if str(r) == reader]
            if not matches:
                return None
            conn = matches[0].createConnection()
            conn.connect()
            try:
                piv_ok = self._select_ok(conn, list(APDU_SELECT_PIV))
                opgp_ok = False
                if piv_ok:
                    opgp_ok = self._select_ok(conn, self._select_openpgp_apdu())
                if piv_ok and opgp_ok:
                    return "dual"
                if piv_ok:
                    return "piv"
                return None
            finally:
                conn.disconnect()
        except Exception:
            return None

    @staticmethod
    def _select_ok(conn, apdu: list) -> bool:
        try:
            _, sw1, sw2 = conn.transmit(list(apdu))
        except Exception:
            return False
        if sw1 == 0x61:
            return True       # selection succeeded, response pending
        return (sw1 << 8) | sw2 == SW_OK

    @staticmethod
    def _select_openpgp_apdu() -> list:
        return ([0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID_PREFIX)]
                + list(OPENPGP_AID_PREFIX))

    def open_session(self, reader: str) -> "CardSession":
        return CardSession(reader)


class CardSession:
    """Exclusive card session for the whole PIV phase (§3.2)."""

    def __init__(self, reader: str, conn: Optional[object] = None) -> None:
        self.reader = reader
        self._ended = False
        self._in_txn = False
        if conn is None:
            from smartcard.scard import SCARD_PROTOCOL_T1, SCARD_SHARE_EXCLUSIVE
            from smartcard.System import readers as system_readers
            matches = [r for r in system_readers() if str(r) == reader]
            if not matches:
                raise CardError(f"reader vanished: {reader}")
            conn = matches[0].createConnection()
            try:
                conn.connect(mode=SCARD_SHARE_EXCLUSIVE, protocol=SCARD_PROTOCOL_T1)
            except Exception:
                # A failed connect leaves the pyscard connection alive with
                # an established PC/SC context; __del__ only fires after the
                # exception traceback cycles are collected, so each retry
                # can hold a pcscd client socket (200-context cap wedged
                # pcscd system-wide on 2026-09-06).  Release it NOW.
                try:
                    conn.release()
                except Exception:
                    pass
                raise
        self.conn = conn
        self._begin()

    @staticmethod
    def _hcard(conn) -> int:
        """Low-level card handle: PCSCCardConnection.hcard, reached
        through CardConnectionDecorator.component when wrapped."""
        inner = getattr(conn, "component", conn)
        h = getattr(inner, "hcard", None)
        if h is None:
            raise CardError("no low-level card handle on this connection")
        return h

    def _begin(self) -> None:
        from smartcard.scard import SCardBeginTransaction
        hresult = SCardBeginTransaction(self._hcard(self.conn))
        if hresult != 0:
            raise CardError(f"SCardBeginTransaction: 0x{hresult:08X}")
        self._in_txn = True

    def transmit(self, apdu: Sequence[int]) -> tuple:
        """Send one APDU (GET RESPONSE on 61xx handled); return (data, sw)."""
        log.debug("APDU > %s", redact(apdu))
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        resp = bytes(data)
        while sw1 == 0x61:
            more, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            resp += bytes(more)
        sw = (sw1 << 8) | sw2
        log.debug("APDU < sw=%04X len=%d", sw, len(resp))
        return resp, sw

    def end(self, reset: bool) -> None:
        """Release the transaction + disconnect.  On the pass path the
        card is reset (SCARD_RESET_CARD) so no verified PIV session
        leaks into the relay phase (§2 hygiene).  Idempotent."""
        if self._ended:
            return
        self._ended = True
        if self._in_txn:
            from smartcard.scard import (
                SCARD_LEAVE_CARD, SCARD_RESET_CARD, SCardEndTransaction,
            )
            disposition = SCARD_RESET_CARD if reset else SCARD_LEAVE_CARD
            try:
                SCardEndTransaction(self._hcard(self.conn), disposition)
            finally:
                self._in_txn = False
        try:
            self.conn.disconnect()
        except Exception:
            pass


# --- HTTP seam (§6.2/§6.3) ---------------------------------------------------

class GateHTTP:
    """mTLS HTTPS client for /v1/challenge + /v1/verify.

    Pinned root CA + client cert (machine identity); hostname checking
    is always on.  Transport errors are raised, never confused with
    verdicts.
    """

    def __init__(self, server_url: str, ca_root: str, client_cert: str,
                 client_key: str, timeout_s: float = 10.0, retries: int = 3,
                 backoff_s: float = 0.5) -> None:
        self.base = server_url.rstrip("/")
        self.timeout = timeout_s
        self.retries = retries
        self.backoff = backoff_s
        self._ctx = ssl.create_default_context(cafile=ca_root)
        self._ctx.load_cert_chain(client_cert, client_key)

    def _post(self, path: str, body: bytes) -> bytes:
        req = urllib.request.Request(
            self.base + path, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(
                    req, timeout=self.timeout, context=self._ctx) as r:
                if r.status != 200:
                    raise TransportError(f"{path}: HTTP {r.status}")
                return r.read()
        except urllib.error.HTTPError as exc:
            # urllib raises HTTPError for non-2xx before the generic
            # handler sees anything; 429 must keep its identity (the
            # bridge backs off instead of looping).
            if exc.code == 429:
                header = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    retry_after = int(header) if header else None
                except (TypeError, ValueError):
                    retry_after = None
                raise RateLimited(f"{path}: HTTP 429 (rate limited)",
                                  retry_after=retry_after) from exc
            raise TransportError(f"{path}: HTTP {exc.code}") from exc
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"{path}: {exc}") from exc

    def challenge(self) -> bytes:
        """§3.7: bounded retry (attempts, short backoff).  Failure here
        is 'auth server unreachable', never a card verdict."""
        last: Optional[Exception] = None
        for attempt in range(max(1, self.retries)):
            if attempt:
                time.sleep(self.backoff)
            try:
                body = self._post("/v1/challenge", b"{}")
            except RateLimited:
                raise               # never re-hammer a rate-limited endpoint
            except TransportError as exc:
                last = exc
                continue
            try:
                doc = json.loads(body)
                nonce = base64.b64decode(doc["nonce"], validate=True)
            except Exception as exc:
                raise TransportError(f"challenge: malformed response: {exc}") from exc
            if len(nonce) != 32:
                raise TransportError(f"challenge: nonce is {len(nonce)}B, want 32")
            return nonce
        raise TransportError(f"challenge failed after {self.retries} attempts: {last}")

    def verify(self, nonce: bytes, signature: bytes, cert: bytes) -> Verdict:
        """§3.9: exactly one attempt.  Both verdicts ride HTTP 200; a
        timeout / non-200 raises TransportError, which ends the gate
        (§6.4 ambiguity rule) — never a blind resend."""
        body = json.dumps({
            "nonce": base64.b64encode(nonce).decode(),
            "signature": base64.b64encode(signature).decode(),
            "cert": base64.b64encode(cert).decode(),
        }).encode()
        raw = self._post("/v1/verify", body)
        try:
            doc = json.loads(raw)
            result = doc["result"]
        except Exception as exc:
            raise TransportError(f"verify: malformed response: {exc}") from exc
        if result == "pass":
            return Verdict("pass")
        if result == "fail":
            return Verdict("fail", doc.get("reason"))
        raise TransportError(f"verify: unknown result {result!r}")

    def totp(self, label: str) -> tuple:
        """POST /v1/totp -> (code, expires_at RFC3339).  The epoch opened
        by the ceremony that produced this GateResult must still be open.
        Fail verdicts ride HTTP 200 like verify; they become
        TransportError (reason in the message) for the caller to log."""
        raw = self._post("/v1/totp", json.dumps({"label": label}).encode())
        try:
            doc = json.loads(raw)
            result = doc["result"]
        except Exception as exc:
            raise TransportError(f"totp: malformed response: {exc}") from exc
        if result != "pass":
            raise TransportError(f"totp refused: {doc.get('reason')}")
        return doc["code"], doc["expires_at"]


# --- card steps --------------------------------------------------------------

def read_gate_cert(session: CardSession) -> bytes:
    """§3.6: GET DATA 5FC105 -> bare leaf DER.  Runs before the challenge
    fetch so it never eats the 10 s nonce TTL budget."""
    resp, sw = session.transmit(APDU_GET_DATA_GATE)
    if sw == 0x6A82:
        # Object not found: a PIV applet without a gate credential —
        # the wrong-card case, not a generic card failure.
        raise NoGateCert(f"GET DATA 5FC105: SW={sw:04X}")
    if sw != SW_OK or not resp:
        raise CardError(f"GET DATA 5FC105: SW={sw:04X}")
    leaf = unwrap_tlv(resp, (0x53, 0x70))
    if len(leaf) < 2 or leaf[0] != 0x30:
        raise CardError("5FC105 payload is not a DER certificate")
    return leaf


def ga_sign(session: CardSession, digest: bytes) -> bytes:
    """§3.8: GENERAL AUTHENTICATE (P2 = 9A) -> DER signature, forwarded
    untouched.  A malformed response raises StaleResponse."""
    resp, sw = session.transmit(apdu_ga(digest))
    if sw != SW_OK:
        raise StaleResponse(f"GA SW={sw:04X} head={resp[:8].hex()}")
    try:
        sig = unwrap_tlv(resp, (0x7C, 0x82))
    except CardError as exc:
        raise StaleResponse(f"GA TLV: {exc} head={resp[:8].hex()}") from exc
    if not sig.startswith(b"\x30"):
        raise StaleResponse(f"GA sig not DER head={resp[:8].hex()}")
    return sig


def prompt_pin(attempts_remaining: Optional[int]) -> bytearray:
    """§3.4: controlling-tty prompt (getpass-style; identical over SSH).
    Returns the raw PIN bytes — the caller zeroizes them."""
    if attempts_remaining is None:
        suffix = ""
    elif attempts_remaining == 1:
        suffix = " (1 attempt remaining!)"
    else:
        suffix = f" ({attempts_remaining} attempts remaining)"
    while True:
        try:
            raw = getpass.getpass(f"PIV PIN{suffix}: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise CardError("no PIN entered") from exc
        if not raw:
            continue
        pin = raw.encode("utf-8")
        if len(pin) > 8:
            print("PIN must be at most 8 bytes; try again.")
            continue
        return bytearray(pin)


# --- the flow ----------------------------------------------------------------

class Gate:
    """Orchestrates §3.  Owns no UHID knowledge: the caller (lifecycle)
    creates/destroys the device from the GateResult."""

    def __init__(self, link: CardLink, http: GateHTTP, audit: Audit, *,
                 reader_filter: Optional[str] = None,
                 prompt: Optional[Callable] = None,
                 ui_ask: Optional[Callable] = None,
                 ui_timeout: float = 20.0,
                 totp_labels: Optional[list] = None) -> None:
        self.link = link
        self.http = http
        self.audit = audit
        self.reader_filter = reader_filter
        self._prompt = prompt or prompt_pin
        self.ui_ask = ui_ask
        self.ui_timeout = ui_timeout
        self.totp_labels = list(totp_labels or [])
        self._want_totp: Optional[str] = None

    def run(self) -> GateResult:
        reader, generation = self.link.wait_for_insertion(self.reader_filter)
        log.info("card inserted (reader=%s generation=%d)", reader, generation)
        give_way = self._arbiter(reader, generation)
        if give_way is not None:
            return self._fail(give_way,
                              f"card left for the {give_way} applet",
                              reader, generation)
        try:
            try:
                result = self._gate_once(reader, generation)
            except StaleResponse:
                # §3.8: malformed GA -> exactly one full re-run on a
                # fresh session, including a fresh PIN.
                log.warning("stale GA response — one full re-run on a fresh session")
                result = self._gate_once(reader, generation)
        except CardError as exc:
            return self._fail("card_error", f"gate aborted: {exc}")
        if result.passed and self._want_totp:
            result.want = self._want_totp
        return result

    def _arbiter(self, reader: str, generation: int) -> Optional[str]:
        """Ask the user what the insertion is for: the gate, the OpenPGP
        applet (dual-applet cards), or a TOTP code for a configured label.

        Advisory only: no answer, no UI, or a single-applet card never
        blocks the gate ceremony — unless TOTP labels are configured, in
        which case PIV-only cards get a picker too (TOTP is a gate-applet
        flow: the ceremony runs and the code rides the epoch it opens).
        ui_ask receives reader/generation so the caller can memoize one
        ask per seated card.  Returns a park reason ("user_ssh" /
        "user_dismissed") or None to proceed with the gate.
        """
        if self.ui_ask is None:
            return None
        kind = self.link.probe_applets(reader)
        dual = kind == "dual"
        if not dual and not (self.totp_labels and kind == "piv"):
            return None
        actions = {"gate": "Gate (passkey)"}
        body = ""
        if dual:
            actions["ssh"] = "SSH (OpenPGP)"
            body = ("This card carries both the gate and the OpenPGP "
                    "applet.\n")
        for label in self.totp_labels:
            actions[f"totp:{label}"] = f"TOTP: {label}"
        actions["dismiss"] = "Not now"
        choice = self.ui_ask(
            "Card inserted — choose the applet",
            body + f"Defaulting to the gate in {int(self.ui_timeout)}s.",
            actions, self.ui_timeout, reader=reader, generation=generation)
        self.audit.log("applet_choice", choice=choice or "timeout",
                       reader=reader, generation=generation)
        if choice == "ssh":
            return "user_ssh"
        if choice == "dismiss":
            return "user_dismissed"
        if isinstance(choice, str) and choice.startswith("totp:"):
            self._want_totp = choice[len("totp:"):]
        return None

    def _gate_once(self, reader: str, generation: int) -> GateResult:
        session = self.link.open_session(reader)
        return self._gating(session, reader, generation)

    def _fail(self, reason: str, message: str, reader: str = None,
              generation: int = None,
              retry_after: int = None) -> GateResult:
        self.audit.log("gate_fail", reason=reason)
        log.error("%s", message)
        return GateResult(False, reason, reader, generation,
                          retry_after=retry_after)

    def _verify_once(self, session: CardSession, cert: bytes,
                     nonce: bytes) -> Verdict:
        digest = hashlib.sha256(PREFIX + nonce).digest()
        sig = ga_sign(session, digest)
        verdict = self.http.verify(nonce, sig, cert)
        self.audit.log("verify",
                       nonce_hash=hashlib.sha256(nonce).hexdigest(),
                       result=verdict.result, reason=verdict.reason)
        return verdict

    def _gating(self, session: CardSession, reader: str,
                generation: int) -> GateResult:
        """§3.3–§3.11 for one acquired session; always ends the session."""
        ended = False
        try:
            # §3.3 SELECT PIV — non-9000 → not a gate card, exit quietly.
            _resp, sw = session.transmit(APDU_SELECT_PIV)
            if sw != SW_OK:
                return self._fail("no_piv_applet", "not a gate card",
                                  reader, generation)
            # §3.4/§3.5 PIN — user-driven loop; server never contacted.
            attempts_remaining: Optional[int] = None
            while True:
                pin = self._prompt(attempts_remaining)
                try:
                    _r, sw = session.transmit(apdu_verify(pad_pin(bytes(pin))))
                finally:
                    for i in range(len(pin)):
                        pin[i] = 0      # §3.5: zeroize immediately
                if sw == SW_OK:
                    break
                if sw >> 8 == 0x63:
                    attempts_remaining = sw & 0x0F
                    print(f"Wrong PIN ({attempts_remaining} attempt(s) remaining).")
                    continue            # user-driven; never auto-retry
                if sw == SW_PIN_BLOCKED:
                    return self._fail("pin_blocked", PUK_MESSAGE,
                                      reader, generation)
                return self._fail("pin_verify_failed", f"VERIFY SW={sw:04X}")
            # §3.6 leaf (pre-network).
            cert = read_gate_cert(session)
            # §3.7 challenge (bounded retry inside the seam).
            nonce = self.http.challenge()
            self.audit.log("challenge",
                           nonce_hash=hashlib.sha256(nonce).hexdigest())
            # §3.8/§3.9 sign + verify, then §6.4 behavior.
            verdict = self._verify_once(session, cert, nonce)
            if (verdict.result == "fail"
                    and verdict.reason in ("nonce_unknown", "nonce_expired")):
                # §6.4: single transparent recovery — refetch + re-sign.
                log.info("nonce %s — refetching once", verdict.reason)
                nonce = self.http.challenge()
                verdict = self._verify_once(session, cert, nonce)
            if verdict.result != "pass":
                reason = verdict.reason or "unknown"
                if reason == "crl_stale":
                    return self._fail(reason,
                                      "gate unavailable (server CRL is stale)")
                return self._fail(reason, f"gate refused: {reason}")
            # §3.10 the pass authorizes THIS insertion.
            if not self.link.still_present(reader, generation):
                return self._fail("card_removed",
                                  "card vanished before activation")
            session.end(reset=True)     # §2 hygiene: clear PIV PIN state
            ended = True
            if not self.link.still_present(reader, generation):
                return self._fail("card_removed", "card vanished during reset")
            self.audit.log("gate_pass", reader=reader, generation=generation)
            return GateResult(True, None, reader, generation)
        except StaleResponse:
            raise                       # run() owns the single re-run
        except RateLimited as exc:
            return self._fail("rate_limited", f"rate limited: {exc}",
                              reader, generation,
                              retry_after=exc.retry_after)
        except NoGateCert as exc:
            return self._fail("no_gate_cert", f"no gate cert: {exc}",
                              reader, generation)
        except TransportError as exc:
            return self._fail("server_unreachable",
                              f"auth server unreachable: {exc}")
        except CardError as exc:
            return self._fail("card_error", f"card error: {exc}")
        finally:
            if not ended:
                session.end(reset=False)