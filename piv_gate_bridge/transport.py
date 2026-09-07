"""POST /ctap transport (spec v1.1 §6.7): one CTAP2 frame in, one
CTAP2 response out, over mTLS HTTPS to the piv-gate server."""

from __future__ import annotations

import ssl
import urllib.request


class TransportError(Exception):
    """The /ctap request could not be completed (TLS, HTTP, timeout)."""


class HttpCtapTransport:
    """CtapTransport seam backed by the gate server's POST /ctap."""

    def __init__(self, server_url: str, ca_root: str, client_cert: str,
                 client_key: str, timeout_s: float = 10.0) -> None:
        self.url = server_url.rstrip("/") + "/ctap"
        self.timeout = timeout_s
        self._ctx = ssl.create_default_context(cafile=ca_root)
        self._ctx.load_cert_chain(client_cert, client_key)

    def call(self, frame: bytes) -> bytes:
        """Send one raw CTAP2 frame; return the raw CTAP2 response
        (status byte + CBOR).  Anything other than HTTP 200 (or any
        transport failure) raises TransportError."""
        req = urllib.request.Request(
            self.url, data=frame,
            headers={"Content-Type": "application/cbor"}, method="POST")
        try:
            with urllib.request.urlopen(
                    req, timeout=self.timeout, context=self._ctx) as r:
                if r.status != 200:
                    raise TransportError(f"/ctap: HTTP {r.status}")
                return r.read()
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(str(exc)) from exc

    def close(self) -> None:
        pass