#!/usr/bin/env python3
"""PIV-gated FIDO2 bridge (fork of fido2-hid-bridge).

Inverted lifecycle (spec v1.1 §2): the UHID device exists iff
(card present) ∧ (gate pass for the current seat session) ∧ (session
not expired).  main() loops:

    gate run -> on pass: create device + monitors
             -> teardown cause ∈ {removed, idle, max_lifetime,
                                  error, sigterm}
             -> destroy + audit -> back to the gate loop

A failed or unreachable gate never creates a device.
"""

import argparse
import asyncio
import logging
import os
import signal
import subprocess
import threading
import time
from typing import Callable, Optional

from piv_gate_bridge.ctap_hid_device import CTAPHIDDevice
from piv_gate_bridge.gate import Audit, CardLink, Gate, GateHTTP
from piv_gate_bridge.transport import HttpCtapTransport
from piv_gate_bridge.ui import notify_info

CAUSES_REMOVED = "removed"
CAUSES_IDLE = "idle"
CAUSES_MAX_LIFETIME = "max_lifetime"
CAUSES_ERROR = "error"
CAUSES_SIGTERM = "sigterm"

PRESENCE_POLL_SECONDS = 1.0
TEARDOWN_POLL_SECONDS = 0.25
PROBE_TIMEOUT_S = 8.0


class LiveSession:
    """The LIVE state: a created UHID device plus its teardown monitors.

    Monitors (all status-only, no card I/O):
      - presence: the card that passed is still seated, same insertion
        generation (§3.10);
      - idle: no CTAPHID traffic for t_idle;
      - max lifetime: t_max since the gate pass;
      - signals / errors: teardown() from the main loop.
    """

    def __init__(self, dev: CTAPHIDDevice, audit: Audit, link: CardLink,
                 reader: str, generation: int, t_idle: float, t_max: float,
                 created: Optional[float] = None) -> None:
        self.dev = dev
        self.audit = audit
        self.link = link
        self.reader = reader
        self.generation = generation
        self.t_idle = t_idle
        self.t_max = t_max
        self.created = created if created is not None else time.time()
        self.cause: Optional[str] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._threads = []
        if self.link is not None:
            self._threads.append(
                threading.Thread(target=self._watch_presence, daemon=True,
                                 name="piv-gate-presence"))
        self._threads.append(
            threading.Thread(target=self._watch_time, daemon=True,
                             name="piv-gate-time"))
        for t in self._threads:
            t.start()

    def teardown(self, cause: str) -> None:
        """Request teardown; the first cause wins.  Idempotent."""
        if self.cause is None:
            self.cause = cause
        self._stop.set()

    def finish(self) -> str:
        """Block until a teardown cause exists, then return it."""
        while self.cause is None:
            self._stop.wait(TEARDOWN_POLL_SECONDS)
        for t in getattr(self, "_threads", []):
            t.join(timeout=5.0)
        return self.cause

    async def finish_async(self) -> str:
        """Async variant of finish() for the main loop: python-uhid's
        AsyncioBlockingUHID dispatches HID I/O on the event loop, so the
        live phase must never block the loop thread while waiting."""
        while self.cause is None:
            await asyncio.sleep(TEARDOWN_POLL_SECONDS)
        loop = asyncio.get_running_loop()
        for t in getattr(self, "_threads", []):
            await loop.run_in_executor(None, lambda t=t: t.join(timeout=5.0))
        return self.cause

    def _watch_presence(self) -> None:
        from concurrent.futures import ThreadPoolExecutor
        probe_failures = 0
        tick = 0
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            while not self._stop.wait(1.0):
                tick += 1
                try:
                    if not self.link.still_present(self.reader,
                                                   self.generation):
                        self.teardown(CAUSES_REMOVED)
                        return
                    # §3.10 probe, every other second: vpcd keeps PRESENT
                    # asserted while the phone app holds the socket, so a
                    # reachable card is confirmed with SELECT PIV.  Two
                    # consecutive failures (or a hung probe, same as a
                    # failure via the 8s timeout) = removal.
                    if tick % 2 == 0:
                        try:
                            alive = pool.submit(
                                self.link.probe_alive,
                                self.reader).result(
                                    timeout=PROBE_TIMEOUT_S)
                        except TimeoutError:
                            alive = False        # hung probe = unreachable
                        probe_failures = 0 if alive else probe_failures + 1
                        if probe_failures >= 2:
                            self.teardown(CAUSES_REMOVED)
                            return
                except Exception as exc:
                    logging.warning("presence monitor: %s", exc)
                    self.teardown(CAUSES_ERROR)
                    return
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _watch_time(self) -> None:
        deadline = self.created + self.t_max
        while not self._stop.wait(1.0):
            now = time.time()
            if now >= deadline:
                self.teardown(CAUSES_MAX_LIFETIME)
                return
            if now >= self.dev.last_activity + self.t_idle:
                self.teardown(CAUSES_IDLE)
                return


class Bridge:
    """Owns the seat-session loop (§2 state machine)."""

    def __init__(self, server_url: str, ca_root: str, client_cert: str,
                 client_key: str, audit_path: str,
                 reader_filter: Optional[str] = None,
                 http_timeout_s: float = 10.0, retries: int = 3,
                 t_idle: float = 600.0, t_max: float = 12 * 3600.0,
                 stub_gate: bool = False,
                 ui_ask: Optional[Callable] = None,
                 ui_timeout: float = 20.0,
                 totp_labels: Optional[list] = None) -> None:
        self.server_url = server_url
        self.ca_root = ca_root
        self.client_cert = client_cert
        self.client_key = client_key
        self.audit = Audit(audit_path)
        self.reader_filter = reader_filter
        self.http_timeout = http_timeout_s
        self.retries = retries
        self.t_idle = t_idle
        self.t_max = t_max
        self.stub_gate = stub_gate
        self.ui_ask = ui_ask
        self.ui_timeout = ui_timeout
        self.totp_labels = list(totp_labels or [])
        self._ask_cache: tuple = (None, None)   # ((reader, gen), choice)
        self.session: Optional[LiveSession] = None
        self._gate_http = None   # reused by the TOTP popup path
        # Set by the signal handler alongside a live-session teardown so
        # the main loop exits instead of re-gating (SIGINT/SIGTERM must
        # stop the process — the systemd unit has Restart=no and a ^C is
        # not a request for another seat session).
        self._signal_exit = False

    # -- gate phase (blocking; runs in a daemon thread) ----------------

    def run_gate(self) -> object:
        if self.stub_gate:
            # Test hook for the no-hardware FIDO e2e: skip the card and
            # the network gate; authorize a synthetic seat session.
            from piv_gate_bridge.gate import GateResult
            return GateResult(True, None, "stub", 0)
        # Fresh PC/SC context per seat session: survives pcscd restarts
        # and releases all card handles between sessions.
        self._gate_link = CardLink()
        http = GateHTTP(self.server_url, self.ca_root, self.client_cert,
                        self.client_key, timeout_s=self.http_timeout,
                        retries=self.retries)
        self._gate_http = http
        gate = Gate(self._gate_link, http, self.audit,
                    reader_filter=self.reader_filter,
                    ui_ask=self._cached_ask if self.ui_ask else None,
                    ui_timeout=self.ui_timeout,
                    totp_labels=self.totp_labels)
        return gate.run()

    def _cached_ask(self, title: str, body: str, actions: dict,
                    timeout_s: float, reader: str = None,
                    generation: int = None) -> Optional[str]:
        """One ask per seated card: a failed gate run re-enters the loop
        and would re-popup every retry (2026-09-08).  A gate-default
        choice (click or timeout) also reclaims the reader from scdaemon,
        which grabs it exclusively after OpenPGP use (it respawns on
        demand — killing it is how the bridge wins the arbitration)."""
        key = (reader, generation)
        if self._ask_cache[0] != key:
            choice = self.ui_ask(title, body, actions, timeout_s)
            self._ask_cache = (key, choice)
        else:
            choice = self._ask_cache[1]
        if choice in (None, "gate") or (
                isinstance(choice, str) and choice.startswith("totp:")):
            # Gate AND totp:<label> both continue into the PIV ceremony,
            # which needs the reader back from scdaemon.
            try:
                subprocess.run(["gpgconf", "--kill", "scdaemon"],
                               capture_output=True, timeout=5)
            except OSError:
                pass
        return choice

    # -- live phase ------------------------------------------------------

    def live_phase(self, result, dev: CTAPHIDDevice) -> str:
        """Blocking variant (tests)."""
        self.audit.log("device_created", reader=result.reader,
                       generation=result.generation)
        link = None if self.stub_gate else self._gate_link
        session = LiveSession(dev, self.audit, link,
                              result.reader, result.generation,
                              self.t_idle, self.t_max)
        self.session = session
        session.start()
        cause = session.finish()
        self.session = None
        dev.destroy()
        self.audit.log("device_destroyed", cause=cause)
        return cause

    async def live_phase_async(self, result, dev: CTAPHIDDevice) -> str:
        """Device is created; run monitors until teardown, then destroy.

        Must not block the event loop: python-uhid's AsyncioBlockingUHID
        reads/writes the UHID fd via loop.add_reader/add_writer, so HID
        traffic dies if the loop thread is blocked in a polling loop.
        """
        self.audit.log("device_created", reader=result.reader,
                       generation=result.generation)
        link = None if self.stub_gate else self._gate_link
        session = LiveSession(dev, self.audit, link,
                              result.reader, result.generation,
                              self.t_idle, self.t_max)
        self.session = session
        session.start()
        cause = await session.finish_async()
        self.session = None
        dev.destroy()
        self.audit.log("device_destroyed", cause=cause)
        return cause

    # -- signals ---------------------------------------------------------

    def install_signal_handlers(self, loop: asyncio.AbstractEventLoop) -> None:
        def on_signal() -> None:
            self._signal_exit = True
            session = self.session
            if session is not None:
                session.teardown(CAUSES_SIGTERM)
            else:
                # GATING or IDLE: nothing to clean up; the gate thread is
                # a daemon and the kernel reaps the (nonexistent) device.
                os._exit(0)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, on_signal)

    # -- main loop ---------------------------------------------------------

    # Fail reasons that mean "the seated card cannot pass" — park until
    # the card physically changes (insertion counter) instead of looping
    # timed retries (a ~1.5 s wrong-card loop wedged pcscd system-wide on
    # 2026-09-07, and a 429 loop sustained the server rate limit).
    # user_ssh / user_dismissed: the user handed the card to another
    # applet (or deferred) via the applet-picker notification.
    PARK_REASONS = ("no_piv_applet", "no_gate_cert", "pin_blocked",
                    "user_ssh", "user_dismissed")

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        self.install_signal_handlers(loop)
        backoff = 1.0
        while True:
            try:
                result = await loop.run_in_executor(None, self.run_gate)
            except Exception as exc:
                # Exponential backoff: a persistent gate failure (stale
                # pcscd reader lock, reader wedged) must not hammer pcscd
                # — every attempt opens PC/SC contexts and a hard retry
                # loop filled pcscd's 200-context cap in ~2 minutes
                # (2026-09-06), taking card access down system-wide.
                logging.error("gate run failed: %s (retry in %.0fs)",
                              exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            if not result.passed:
                reason = result.reason
                if reason in self.PARK_REASONS and result.reader:
                    await self._park(result)
                    continue
                if reason == "rate_limited":
                    delay = min(max(result.retry_after or 30, 30), 300.0)
                    logging.warning("server rate limited (retry in %.0fs)",
                                    delay)
                    await asyncio.sleep(delay)
                    continue
                # Any other fail gets the same escalation as exceptions;
                # the reset below fires only on a pass.
                logging.error("gate refused (%s); retry in %.0fs",
                              reason, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            backoff = 1.0
            want = getattr(result, "want", None)
            if want:
                # TOTP popup path: the ceremony already happened; show the
                # code and park instead of creating the UHID device.
                await self._totp_then_park(result, want)
                if self._signal_exit:
                    return
                continue
            transport = HttpCtapTransport(
                self.server_url, self.ca_root, self.client_cert,
                self.client_key, timeout_s=self.http_timeout)
            dev = CTAPHIDDevice(transport=transport)
            await dev.start()
            cause = await self.live_phase_async(result, dev)
            transport.close()
            # Drop the gate link with the session: a "removed" teardown's
            # zombie presence monitor can still be probing on this context
            # when the next gate run connects (0x8010000B, 2026-09-08).
            self._gate_link = None
            if self._signal_exit:
                return
            logging.info("session ended (%s); waiting for next insertion", cause)

    async def _park(self, result) -> None:
        """Wait until the seated card changes; no card I/O, no retries.

        The gate link (PC/SC context) from the failed attempt is reused
        for the generation wait, then dropped so the next gate run gets
        a fresh context (the existing pcscd-restart recovery path)."""
        ssh = result.reason == "user_ssh"
        self.audit.log("gate_park", reason=result.reason,
                       reader=result.reader, generation=result.generation)
        if ssh:
            logging.warning("card released for SSH — parked until swapped")
        else:
            logging.warning(
                "not a gate card (%s) — parked until the card is swapped",
                result.reason)
        link = self._gate_link
        try:
            loop = asyncio.get_running_loop()
            if ssh:
                # scdaemon takes the reader exclusively for OpenPGP; make
                # gpg-agent learn the card's keys so ssh just works.
                await loop.run_in_executor(None, self._ssh_handoff)
            await loop.run_in_executor(
                None, link.wait_for_generation_change,
                result.reader, result.generation)
        except Exception as exc:
            logging.warning("park wait failed (%s); re-gating", exc)
        finally:
            self._gate_link = None
        self.audit.log("gate_unpark", reason=result.reason)

    async def _totp_then_park(self, result, label: str) -> None:
        """The user picked TOTP in the applet picker and the gate
        ceremony passed: fetch the code via the same mTLS HTTP session
        (the epoch this pass opened must still be open server-side) and
        show it as a notification.  No UHID device is created; the
        bridge parks until the card is swapped."""
        code = None
        try:
            loop = asyncio.get_running_loop()
            code, expires_at = await loop.run_in_executor(
                None, self._gate_http.totp, label)
        except Exception as exc:
            # Refusal (unknown_label, epoch_closed) or transport failure:
            # say so on screen — a silent park looks like the popup ate it.
            logging.error("totp %s: %s", label, exc)
            notify_info(f"TOTP {label} failed", str(exc), timeout_s=10.0)
        if code is not None:
            self.audit.log("totp_shown", label=label)
            notify_info(f"TOTP {label}",
                        f"{code} — valid until {expires_at}",
                        timeout_s=30.0)
        link = self._gate_link
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, link.wait_for_generation_change,
                result.reader, result.generation)
        except Exception as exc:
            logging.warning("totp park wait failed (%s); re-gating", exc)
        finally:
            self._gate_link = None
        self.audit.log("gate_unpark", reason="totp_done",
                       reader=result.reader, generation=result.generation)

    def _ssh_handoff(self) -> None:
        """Register the card's OpenPGP keys with gpg-agent (SCD LEARN);
        scdaemon then holds the reader exclusively until the card leaves."""
        try:
            subprocess.run(["gpg-connect-agent", "SCD LEARN --force", "/bye"],
                           capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            logging.warning("SCD LEARN failed: %s", exc)
        notify_info("Card in use for SSH",
                    "The gate is parked until this card is swapped out.",
                    timeout_s=15.0)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="PIV-gated FIDO2 bridge", allow_abbrev=False)
    parser.add_argument("--config", required=True,
                        help="path to the TOML config (spec §8)")
    parser.add_argument("--debug", action="store_const", const=logging.DEBUG,
                        default=logging.INFO, help="Enable debug messages")
    parser.add_argument("--gate-stub-pass", action="store_true",
                        help="TEST ONLY: skip the card gate and authorize "
                             "a synthetic session (no-hardware e2e)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.debug)

    from piv_gate_bridge.config import Config
    cfg = Config.load(args.config)
    ui_ask = None
    if cfg.prompt_on_ambiguous:
        from piv_gate_bridge import ui as ui_mod
        ui_ask = ui_mod.notify_ask
    bridge = Bridge(cfg.server_url, cfg.ca_root, cfg.client_cert,
                    cfg.client_key, cfg.audit_log,
                    reader_filter=cfg.reader_filter,
                    http_timeout_s=cfg.http_timeout, retries=cfg.retries,
                    t_idle=cfg.t_idle, t_max=cfg.t_max,
                    stub_gate=args.gate_stub_pass,
                    ui_ask=ui_ask, ui_timeout=cfg.prompt_timeout,
                    totp_labels=cfg.totp_labels)
    asyncio.run(bridge.run())


if __name__ == "__main__":
    main()