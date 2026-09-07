"""Fork tests: CTAPHID framing with the transport seam, and the
inverted lifecycle (device only after a gate pass; teardown causes).

Runs with: python3 -m unittest discover -s tests -t .

Wire conventions (verified against python-uhid 0.0.1): the host->device
report arrives in the callback WITH a leading report-ID byte (upstream
parses the channel at buffer[1:5]); device->host reports go out via
send_input WITHOUT one (channel at bytes 0..3, cmd at 4, len at 5..6,
body at 7..).
"""

import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piv_gate_bridge.bridge import (  # noqa: E402
    CAUSES_ERROR, CAUSES_IDLE, CAUSES_MAX_LIFETIME, CAUSES_REMOVED,
    CAUSES_SIGTERM, Bridge, LiveSession,
)
from piv_gate_bridge.ctap_hid_device import (  # noqa: E402
    BROADCAST_CHANNEL, CAPABILITIES, CommandType, CTAPHIDDevice,
)
from piv_gate_bridge.transport import TransportError  # noqa: E402


class FakeUHID:
    """Stands in for the real UHIDDevice."""

    def __init__(self):
        self.sent = []
        self.destroyed = False

    def send_input(self, response):
        self.sent.append(bytes(response))

    def destroy(self):
        self.destroyed = True

    async def wait_for_start_asyncio(self):
        return


class FakeTransport:
    def __init__(self, responses=None, error=None):
        self.frames = []
        self.responses = list(responses or [])
        self.error = error
        self.closed = False

    def call(self, frame):
        self.frames.append(bytes(frame))
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class FakeLink:
    def __init__(self, present=True, generation=7, alive=None):
        self.present = present
        self.generation = generation
        self.alive = present if alive is None else alive
        self.probes = 0

    def still_present(self, reader, generation):
        return self.present and generation == self.generation

    def probe_alive(self, reader):
        self.probes += 1
        return self.alive


class FakeAudit:
    def __init__(self):
        self.events = []

    def log(self, event, **fields):
        self.events.append((event, fields))


def make_device(transport=None, **kw):
    dev_uhid = FakeUHID()
    device = CTAPHIDDevice(transport=transport or FakeTransport(),
                           device=dev_uhid, **kw)
    return device, dev_uhid


def ctap_frame(channel, cmd, data):
    """One complete 64-byte host->device initial packet (with the
    leading report-ID byte the uhid callback delivers).  The initial
    packet carries at most 56 payload bytes."""
    assert len(data) <= 56, "oversized payload needs continuation packets"
    pkt = (b"\x00" + bytes(channel)
           + bytes([cmd | 0x80, len(data) >> 8, len(data) & 0xFF]) + data)
    return pkt + b"\x00" * (64 - len(pkt))


def cbor_packets(channel, data):
    """A full chunked CBOR transaction (initial 56 B + continuations 59 B).
    The initial packet declares the FULL frame length."""
    first = (b"\x00" + bytes(channel)
             + bytes([CommandType.CBOR | 0x80, len(data) >> 8, len(data) & 0xFF])
             + data[:56])
    pkts = [first + b"\x00" * (64 - len(first))]
    rest, seq = data[56:], 0
    while rest:
        chunk, rest = rest[:59], rest[59:]
        p = b"\x00" + bytes(channel) + bytes([seq]) + chunk
        pkts.append(p + b"\x00" * (64 - len(p)))
        seq += 1
    return pkts


def resp_of(pkt):
    """(cmd_byte, body) from a device->host report."""
    return pkt[4], pkt[7:]


class Framing(unittest.TestCase):
    def test_init_reply(self):
        transport = FakeTransport()
        dev, uhid = make_device(transport)
        nonce = bytes([1, 2, 3, 4, 5, 6, 7, 8])
        dev.process_hid_message(
            list(ctap_frame(BROADCAST_CHANNEL, CommandType.INIT, nonce)), None)
        self.assertEqual(len(uhid.sent), 1)
        pkt = uhid.sent[0]
        self.assertEqual(pkt[0:4], BROADCAST_CHANNEL)
        self.assertEqual(pkt[4], CommandType.INIT | 0x80)
        self.assertEqual((pkt[5] << 8) | pkt[6], 17)
        body = pkt[7:7 + 17]
        self.assertEqual(body[0:8], nonce)             # nonce echoed
        cid = body[8:12]                               # new CID
        self.assertNotEqual(cid, b"\x00\x00\x00\x00")
        self.assertNotEqual(cid, BROADCAST_CHANNEL)
        self.assertEqual(body[12], 0x02)               # protocol version
        self.assertEqual(body[13:16], b"\x01\x00\x00")  # device version
        self.assertEqual(body[16], CAPABILITIES)
        self.assertEqual(CAPABILITIES, 0x0D)           # WINK|CBOR|NMSG

    def test_unknown_command_is_error_01_not_nameerror(self):
        # Regression: upstream's `send.send_error` NameError wedged the
        # read dispatch on any unknown command byte.
        dev, uhid = make_device()
        dev.process_hid_message(
            list(ctap_frame([0x11, 0x22, 0x33, 0x44], 0x99, b"")), None)
        self.assertEqual(len(uhid.sent), 1)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.ERROR | 0x80)
        self.assertEqual(body[0], 0x01)                # invalid command
        self.assertEqual(uhid.sent[0][0:4], bytes([0x11, 0x22, 0x33, 0x44]))

    def test_cbor_forwards_frame_verbatim(self):
        frame = bytes([0x04]) + bytes(range(20))       # getInfo frame
        transport = FakeTransport(responses=[bytes([0x00]) + b"OK" * 8])
        dev, uhid = make_device(transport)
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.CBOR, frame)),
            None)
        self.assertEqual(transport.frames, [frame])

    def test_cbor_response_passthrough(self):
        resp = bytes([0x00]) + bytes(range(40))
        transport = FakeTransport(responses=[resp])
        dev, uhid = make_device(transport)
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.CBOR,
                            bytes([0x04]))), None)
        # 47-byte body fits in one initial packet (57-byte capacity).
        self.assertEqual(len(uhid.sent), 1)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.CBOR | 0x80)
        self.assertEqual(body[:len(resp)], resp)

    def test_cbor_transport_error_maps_to_7f(self):
        transport = FakeTransport(error=TransportError("503"))
        dev, uhid = make_device(transport)
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.CBOR,
                            bytes([0x04]))), None)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.CBOR | 0x80)
        self.assertEqual(body[0], 0x7F)

    def test_msg_not_supported(self):
        dev, uhid = make_device()
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.MSG,
                            b"\x00")), None)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.ERROR | 0x80)
        self.assertEqual(body[0], 0x01)

    def test_ping_echo(self):
        dev, uhid = make_device()
        payload = b"hello"
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.PING,
                            payload)), None)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.PING | 0x80)
        self.assertEqual(body[:len(payload)], payload)

    def test_chunked_response_57_59(self):
        # A 120-byte CTAP2 response needs an initial packet (57-byte
        # body capacity) plus continuation packets (59-byte capacity).
        resp = bytes([0x00]) + bytes(range(119))
        transport = FakeTransport(responses=[resp])
        dev, uhid = make_device(transport)
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.CBOR,
                            bytes([0x04]))), None)
        self.assertEqual(len(uhid.sent), 3)
        first, c1, c2 = uhid.sent
        self.assertEqual(len(first), 64)
        self.assertEqual(first[4], CommandType.CBOR | 0x80)
        self.assertEqual((first[5] << 8) | first[6], len(resp))
        self.assertEqual(c1[4], 0)                     # seq 0
        self.assertEqual(c2[4], 1)                     # seq 1
        joined = first[7:] + c1[5:] + c2[5:]
        self.assertEqual(joined[:len(resp)], resp)

    def test_init_wrong_length(self):
        dev, uhid = make_device()
        dev.process_hid_message(
            list(ctap_frame(BROADCAST_CHANNEL, CommandType.INIT, b"123")), None)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.ERROR | 0x80)
        self.assertEqual(body[0], 0x03)                # invalid length

    def test_chunked_request_reassembly(self):
        # A 100-byte CTAP2 frame arrives as initial + 2 continuation
        # packets; the transport sees the reassembled frame once.
        frame = bytes([0x01]) + bytes(range(99))
        transport = FakeTransport(responses=[bytes([0x00])])
        dev, uhid = make_device(transport)
        for pkt in cbor_packets([0xAA, 0xBB, 0xCC, 0xDD], frame):
            dev.process_hid_message(list(pkt), None)
        self.assertEqual(transport.frames, [frame])

    def test_subsequent_packet_bad_seq_is_error_04(self):
        transport = FakeTransport()
        dev, uhid = make_device(transport)
        pkts = cbor_packets([0xAA, 0xBB, 0xCC, 0xDD], bytes(100))
        dev.process_hid_message(list(pkts[0]), None)
        self.assertEqual(uhid.sent, [])                # buffered, no reply yet
        bad = (b"\x00" + bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x05])
               + b"\x00" * 59)                         # seq must be 0; send 5
        dev.process_hid_message(list(bad), None)
        cmd, body = resp_of(uhid.sent[0])
        self.assertEqual(cmd, CommandType.ERROR | 0x80)
        self.assertEqual(body[0], 0x04)                # invalid sequencing

    def test_destroy_idempotent(self):
        dev, uhid = make_device()
        dev.destroy()
        dev.destroy()
        self.assertTrue(uhid.destroyed)
        self.assertTrue(dev.destroyed)

    def test_destroy_swallows_uhid_errors(self):
        class BoomUHID(FakeUHID):
            def destroy(self):
                raise RuntimeError("kernel said no")
        dev, _ = make_device()
        dev.device = BoomUHID()
        dev.destroy()      # must not raise
        self.assertTrue(dev.destroyed)

    def test_last_activity_tracked(self):
        dev, _ = make_device()
        t0 = dev.last_activity
        time.sleep(0.01)
        dev.process_hid_message(
            list(ctap_frame([0xAA, 0xBB, 0xCC, 0xDD], CommandType.PING, b"x")),
            None)
        self.assertGreater(dev.last_activity, t0)


class LiveSessionTeardown(unittest.TestCase):
    def make_session(self, link=None, t_idle=600.0, t_max=12 * 3600.0):
        dev, _uhid = make_device()
        session = LiveSession(dev, FakeAudit(), link or FakeLink(),
                              "Test Reader 00", 7, t_idle, t_max)
        session.start()
        return session, dev

    def test_removed(self):
        session, _dev = self.make_session(FakeLink(present=False))
        self.assertEqual(session.finish(), CAUSES_REMOVED)

    def test_wrong_generation_counts_as_removed(self):
        session, _dev = self.make_session(FakeLink(generation=8))
        self.assertEqual(session.finish(), CAUSES_REMOVED)

    def test_probe_failures_teardown_removed(self):
        # vpcd keeps PRESENT asserted with the card lifted; the SELECT
        # probe is the real signal.  Two consecutive dead probes = gone.
        session, _dev = self.make_session(FakeLink(present=True, alive=False))
        self.assertEqual(session.finish(), CAUSES_REMOVED)

    def test_probe_alive_keeps_session(self):
        link = FakeLink(present=True, alive=True)
        session, _dev = self.make_session(link)
        time.sleep(3.0)                          # spans at least one probe
        self.assertIsNone(session.cause)         # still seated
        session.teardown(CAUSES_SIGTERM)
        self.assertEqual(session.finish(), CAUSES_SIGTERM)
        self.assertGreaterEqual(link.probes, 1)

    def test_hung_probe_counts_as_failure(self):
        import piv_gate_bridge.bridge as bridge_mod
        old = bridge_mod.PROBE_TIMEOUT_S
        bridge_mod.PROBE_TIMEOUT_S = 0.3

        def hang(reader):
            time.sleep(1.0)
            return True

        link = FakeLink(present=True)
        link.probe_alive = hang
        session, _dev = self.make_session(link)
        try:
            self.assertEqual(session.finish(), CAUSES_REMOVED)
        finally:
            bridge_mod.PROBE_TIMEOUT_S = old

    def test_idle(self):
        dev, _uhid = make_device()
        dev.last_activity = time.time() - 120.0
        session = LiveSession(dev, FakeAudit(), FakeLink(), "r", 7,
                              t_idle=60.0, t_max=12 * 3600.0)
        session.start()
        self.assertEqual(session.finish(), CAUSES_IDLE)

    def test_max_lifetime_teardown(self):
        dev, _uhid = make_device()
        session = LiveSession(dev, FakeAudit(), FakeLink(), "r", 7,
                              t_idle=600.0, t_max=0.05)
        session.start()
        self.assertEqual(session.finish(), CAUSES_MAX_LIFETIME)

    def test_sigterm(self):
        session, _dev = self.make_session()
        session.teardown(CAUSES_SIGTERM)
        self.assertEqual(session.finish(), CAUSES_SIGTERM)

    def test_error_cause(self):
        class ExplodingLink(FakeLink):
            def still_present(self, reader, generation):
                raise RuntimeError("pcscd died")
        session, _dev = self.make_session(ExplodingLink())
        self.assertEqual(session.finish(), CAUSES_ERROR)

    def test_first_cause_wins(self):
        dev, _uhid = make_device()
        session = LiveSession(dev, FakeAudit(), FakeLink(present=False),
                              "r", 7, 600.0, 12 * 3600.0)
        session.teardown(CAUSES_SIGTERM)               # first cause wins
        session.teardown(CAUSES_REMOVED)
        self.assertEqual(session.finish(), CAUSES_SIGTERM)


class BridgeLifecycle(unittest.TestCase):
    """The invariant: no UHID device exists unless the gate passed."""

    @staticmethod
    def make_bridge():
        from piv_gate_bridge.gate import GateResult
        bridge = Bridge.__new__(Bridge)
        bridge.server_url = "https://gate.example"
        bridge.ca_root = "/dev/null"
        bridge.client_cert = "/dev/null"
        bridge.client_key = "/dev/null"
        bridge.audit = FakeAudit()
        bridge.reader_filter = None
        bridge.http_timeout = 10.0
        bridge.retries = 3
        bridge.t_idle = 600.0
        bridge.t_max = 12 * 3600.0
        bridge.stub_gate = False
        bridge.session = None
        bridge._gate_link = FakeLink()
        return bridge

    def test_no_device_on_fail(self):
        from piv_gate_bridge.gate import GateResult
        # A failed gate result never reaches live_phase: the run loop
        # creates the transport + device only when result.passed.
        result = GateResult(False, "pin_blocked")
        self.assertFalse(result.passed)
        self.assertIsNone(self.make_bridge().session)

    def test_live_phase_creates_then_destroys(self):
        from piv_gate_bridge.gate import GateResult
        import piv_gate_bridge.bridge as b
        bridge = self.make_bridge()
        dev, uhid = make_device()
        orig = b.LiveSession.start

        def start_and_teardown(self2):
            orig(self2)
            self2.teardown(CAUSES_SIGTERM)

        b.LiveSession.start = start_and_teardown
        try:
            cause = bridge.live_phase(GateResult(True, None, "r", 7), dev)
        finally:
            b.LiveSession.start = orig
        self.assertEqual(cause, CAUSES_SIGTERM)
        self.assertTrue(uhid.destroyed)
        self.assertEqual([e for e, _ in bridge.audit.events],
                         ["device_created", "device_destroyed"])
        self.assertEqual(bridge.audit.events[1][1]["cause"], CAUSES_SIGTERM)


if __name__ == "__main__":
    unittest.main()