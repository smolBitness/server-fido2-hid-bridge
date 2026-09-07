# piv-gate-bridge

A fork of [fido2-hid-bridge](https://github.com/BryanJacobs/fido2-hid-bridge)
(upstream MIT) with an inverted device lifecycle and an HTTPS CTAP2
transport seam. It is the bridge component of the piv-gate stack; see the
companion [Rolki-Server](https://github.com/smolBitness/Rolki-Server)
repository for the server, the keymaster, and the protocol spec.

Upstream relays CTAPHID between a virtual UHID device and a PC/SC card.
This fork changes the model:

- The UHID FIDO2 device exists **only after a gate pass** and is destroyed
  on teardown (idle, max lifetime, card removal, error, or signal). A
  failed or unreachable gate never creates a device.
- The PC/SC card relay is replaced by an mTLS HTTPS transport: CTAP2
  frames are forwarded verbatim to the server-side authenticator
  (`POST /ctap`); there is no card I/O during the live phase.
- The gate phase (card present, PIN prompt on a controlling tty, fresh
  nonce signed by the card's PIV 9A key) runs per seat session.

## Run

```sh
poetry install
poetry run piv-gate-bridge --config ~/.config/piv-gate/config.toml
```

or `systemctl --user start piv-gate-bridge` with the provided
user-level `piv-gate-bridge.service`. Tests:

```sh
python3 -m unittest discover -s tests -t .
```

`tools/e2e_fido2_client.py` is a no-hardware FIDO2 e2e client that drives
the virtual device exactly as a browser would (also mirrored in
Rolki-Client).

License: MIT (upstream, Bryan Jacobs -- see `LICENSE`).
