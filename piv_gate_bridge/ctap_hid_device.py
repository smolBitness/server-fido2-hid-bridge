import logging
import time
from enum import IntEnum
from random import randint
from typing import Optional, Tuple, List

try:
    from uhid import UHIDDevice, AsyncioBlockingUHID, Bus
except ImportError:  # tests inject a fake device; runtime requires uhid
    UHIDDevice = None

from piv_gate_bridge.transport import TransportError

MAX_SIMULTANEOUS_CONNECTIONS = 100
"""How many simultaneous connections to allow open at one time."""
INACTIVITY_CLEANUP_SECONDS = 30.0
"""How many seconds a connection is allowed to remain idle before being closed."""
VID = 0x9999
"""USB vendor ID."""
PID = 0x9999
"""USB product ID."""

BROADCAST_CHANNEL = bytes([0xFF, 0xFF, 0xFF, 0xFF])
"""Standard CTAP-HID broadcast channel."""

# Capabilities byte for INIT responses (§2): WINK | CBOR | NMSG.
# NMSG: CTAP1/U2F messages are not supported — handle_msg answers 0x01.
CAPABILITIES = 0x0D

PROTOCOL_VERSION = 0x02
DEVICE_VERSION = (0x01, 0x00, 0x00)


class CommandType(IntEnum):
    """Catalog of CTAP-HID command type bytes."""

    PING = 0x01
    MSG = 0x03
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    KEEPALIVE = 0x3B
    ERROR = 0x3F


class CTAPHIDDevice:
    """CTAPHID relay over a virtual UHID device.

    Inverted lifecycle (fork core change): the caller creates this
    object ONLY after a gate pass, and calls destroy() on teardown.
    CTAP2 frames are forwarded verbatim to `transport` (the server-side
    authenticator); there is no PC/SC card I/O here.
    """

    device: object
    """Underlying UHID device (or a test fake)."""
    channels_to_state: dict = {}
    """
    Mapping from channel strings to receive buffer state.

    Each value consists of:
    1. The command type in use on the channel
    2. The total length of the incoming request
    3. The sequence number of the most recently received packet (-1 for initial)
    4. The accumulated data received on the channel
    """
    reference_count = 0
    """Number of open handles to the device: clear state when it hits zero."""

    def __init__(self, transport, device: Optional[object] = None):
        self.transport = transport
        self._destroyed = False
        self.last_activity = time.time()
        """Monotonic timestamp of the last CTAPHID packet (idle monitor)."""
        if device is None:
            device = UHIDDevice(
                vid=VID,
                pid=PID,
                name="FIDO2 Virtual USB Device",
                report_descriptor=[
                    0x06,
                    0xD0,
                    0xF1,  # Usage Page (FIDO)
                    0x09,
                    0x01,  # Usage (CTAPHID)
                    0xA1,
                    0x01,  # Collection (Application)
                    0x09,
                    0x20,  # Usage (Data In)
                    0x15,
                    0x00,  # Logical min (0)
                    0x26,
                    0xFF,
                    0x00,  # Logical max (255)
                    0x75,
                    0x08,  # Report Size (8)
                    0x95,
                    0x40,  # Report count (64 bytes per packet)
                    0x81,
                    0x02,  # Input(HID_Data | HID_Absolute | HID_Variable)
                    0x09,
                    0x21,  # Usage (Data Out)
                    0x15,
                    0x00,  # Logical min (0)
                    0x26,
                    0xFF,
                    0x00,  # Logical max (255)
                    0x75,
                    0x08,  # Report Size (8)
                    0x95,
                    0x40,  # Report count (64 bytes per packet)
                    0x91,
                    0x02,  # Output(HID_Data | HID_Absolute | HID_Variable)
                    0xC0,  # End Collection
                ],
                backend=AsyncioBlockingUHID,
                version=0,
                bus=Bus.USB,
            )
            device.receive_output = self.process_hid_message
            device.receive_close = self.process_close
            device.receive_open = self.process_open
        self.device = device
        self.channels_to_state = {}

    def destroy(self) -> None:
        """Remove the UHID device (§2 teardown).  Idempotent."""
        if self._destroyed:
            return
        self._destroyed = True
        try:
            self.device.destroy()
        except Exception as e:
            logging.warning(f"uhid destroy: {e}")

    @property
    def destroyed(self) -> bool:
        return self._destroyed

    def process_open(self):
        self.reference_count += 1

    def process_close(self):
        if self.reference_count > 0:
            self.reference_count -= 1
        if self.reference_count == 0:
            # Clear all state
            self.channels_to_state = {}

    def process_hid_message(self, buffer: List[int], report_type) -> None:
        """Core method: handle incoming HID messages."""
        recvd_bytes = bytes(buffer)
        self.last_activity = time.time()
        logging.debug(f"GOT MESSAGE (type {report_type}): {recvd_bytes.hex()}")

        now = time.time()
        stale_channels = set()
        for channel, data in self.channels_to_state.items():
            if now - data[4] >= INACTIVITY_CLEANUP_SECONDS:
                stale_channels.add(channel)
        for channel in stale_channels:
            del self.channels_to_state[channel]

        if self.is_initial_packet(recvd_bytes):
            packet_or_none = self.parse_initial_packet(recvd_bytes)
            if packet_or_none is None:
                return
            channel, lc, cmd, data = packet_or_none
            channel_key = self.get_channel_key(channel)
            logging.debug(
                f"CMD {cmd.name} CHANNEL {channel_key} len {lc} (recvd {len(data)}) data {data.hex()}"
            )
            self.channels_to_state[channel_key] = cmd, lc, -1, data, now
            if lc == len(data):
                # Complete receive
                self.finish_receiving(channel)
        else:
            channel, seq, new_data = self.parse_subsequent_packet(recvd_bytes)
            channel_key = self.get_channel_key(channel)
            if channel_key not in self.channels_to_state:
                self.send_error(channel, 0x0B)
                return
            cmd, lc, prev_seq, existing_data, _ = self.channels_to_state[channel_key]
            if seq != prev_seq + 1:
                self.handle_cancel(channel, b"")
                self.send_error(channel, 0x04)
                return
            remaining = lc - len(existing_data)
            data = existing_data + new_data[:remaining]
            self.channels_to_state[channel_key] = cmd, lc, seq, data, now
            logging.debug(f"After receive, we have {len(data)} bytes out of {lc}")
            if lc == len(data):
                self.finish_receiving(channel)

    async def start(self):
        await self.device.wait_for_start_asyncio()

    def parse_initial_packet(
        self, buffer: bytes
    ) -> Optional[Tuple[bytes, int, CommandType, bytes]]:
        """Parse an incoming initial packet."""
        logging.debug(f"Initial packet {buffer.hex()}")
        channel = buffer[1:5]
        cmd_byte = buffer[5] & 0x7F
        lc = (int(buffer[6]) << 8) + buffer[7]
        data = buffer[8 : 8 + lc]
        try:
            cmd = CommandType(cmd_byte)
        except ValueError:
            self.send_error(channel, 0x01)
            return None
        return channel, lc, cmd, data

    def is_initial_packet(self, buffer: bytes) -> bool:
        """Return true if packet is the start of a new sequence."""
        if buffer[5] & 0x80 == 0:
            return False
        return True

    def assign_channel_id(self) -> List[int]:
        """Create a new, random, channel ID."""
        for _ in range(10):
            cid = [randint(0, 255) for _ in range(4)]
            if bytes(cid) in (b"\x00\x00\x00\x00", BROADCAST_CHANNEL):
                continue
            if self.get_channel_key(cid) in self.channels_to_state:
                continue
            return cid
        raise ValueError("Unable to assign an unused channel ID!")

    def handle_init(self, channel: bytes, buffer: bytes) -> Optional[bytes]:
        """Initialize or re-initialize a channel."""
        logging.debug(f"INIT on channel {channel}")

        if len(buffer) != 8:
            self.send_error(BROADCAST_CHANNEL, 0x03)
            return None

        if channel == BROADCAST_CHANNEL:
            if len(self.channels_to_state) > MAX_SIMULTANEOUS_CONNECTIONS:
                self.send_error(channel, 0x06)
                return None

            new_channel = self.assign_channel_id()
        else:
            self.handle_cancel(channel, b"")
            new_channel = channel

        return bytes(
            [_ for _ in buffer]
            + [_ for _ in new_channel]
            + [
                PROTOCOL_VERSION,
                DEVICE_VERSION[0],
                DEVICE_VERSION[1],
                DEVICE_VERSION[2],
                CAPABILITIES,
            ]
        )

    def handle_cbor(self, channel: List[int], buffer: bytes) -> Optional[bytes]:
        """Forward one CTAP2 frame to the transport (server-side
        authenticator).  The transport's response (status byte + CBOR)
        goes back verbatim; a transport failure surfaces as CTAP2 0x7F."""
        try:
            return self.transport.call(bytes(buffer))
        except TransportError as e:
            logging.info(f"transport error on /ctap: {e}")
            return bytes([0x7F])

    def handle_cancel(self, channel: List[int], buffer: bytes) -> Optional[bytes]:
        channel_key = self.get_channel_key(channel)
        if channel_key in self.channels_to_state:
            del self.channels_to_state[channel_key]
        return bytes()

    def handle_wink(self, channel: List[int], buffer: bytes) -> Optional[bytes]:
        """Do nothing; there is nothing to wink."""
        return bytes()

    def handle_msg(self, channel: List[int], buffer: bytes) -> Optional[bytes]:
        """CTAP1/U2F is not supported (NMSG capability) — protocol error."""
        self.send_error(channel, 0x01)
        return None

    def handle_ping(self, channel: List[int], buffer: bytes) -> Optional[bytes]:
        """Handle an echo request."""
        return buffer

    def handle_keepalive(self, channel: List[int], buffer: bytes) -> Optional[bytes]:
        """Placeholder: always returns that the device is processing."""
        return bytes([1])

    def encode_response_packets(
        self,
        channel: List[int],
        cmd: CommandType,
        data: bytes,
        packet_size: int = 64,
    ) -> List[bytes]:
        """Chunk response data to be delivered over USB."""
        offset_start = 0
        seq = 0
        responses = []
        while True:
            if seq == 0:
                capacity = packet_size - 7
                chunk = data[offset_start : (offset_start + capacity)]
                data_len_upper = len(data) >> 8
                data_len_lower = len(data) % 256
                response = (
                    bytes(channel)
                    + bytes([cmd | 0x80, data_len_upper, data_len_lower])
                    + chunk
                )
            else:
                capacity = packet_size - 5
                chunk = data[offset_start : (offset_start + capacity)]
                response = bytes(channel) + bytes([seq - 1]) + chunk

            padding_byte_count = packet_size - len(response)
            if padding_byte_count > 0:
                response = response + bytes([0x00] * padding_byte_count)

            responses.append(bytes(response))
            offset_start += capacity
            seq += 1

            if offset_start >= len(data):
                break

        return responses

    def get_channel_key(self, channel: List[int]) -> str:
        return bytes(channel).hex()

    def send_error(self, channel: List[int], error_type: int) -> None:
        responses = self.encode_response_packets(
            channel, CommandType.ERROR, bytes([error_type])
        )
        for response in responses:
            self.device.send_input(response)

    def finish_receiving(self, channel: List[int]) -> None:
        """When finished receiving packets, act on them."""
        channel_key = self.get_channel_key(channel)
        cmd, _, _, data, _ = self.channels_to_state[channel_key]
        self.handle_cancel(channel, b"")

        try:
            handler = getattr(self, f"handle_{cmd.name.lower()}", None)
            if handler is not None:
                response_body = handler(channel, data)
                if response_body is None:
                    # Already dealt with
                    return
                responses = self.encode_response_packets(channel, cmd, response_body)
            else:
                self.send_error(channel, 0x01)
                return
        except Exception as e:
            logging.warning(f"Error: {e}")
            self.send_error(channel, 0x7F)
            return

        for response in responses:
            self.device.send_input(response)

    def parse_subsequent_packet(self, data: bytes) -> Tuple[bytes, int, bytes]:
        """Parse a non-initial packet."""
        return data[1:5], data[5], data[6:]