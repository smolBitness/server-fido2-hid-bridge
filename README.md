# piv-gate-bridge

The workstation-side half of the piv-gate stack: a small daemon that
watches smart-card readers and turns a card tap into (optionally) a
usable FIDO2 authenticator. A fork of
[fido2-hid-bridge](https://github.com/BryanJacobs/fido2-hid-bridge)
(upstream MIT) with the device lifecycle inverted and the card relay
replaced by an HTTPS transport. The server side, the keymaster, and the
protocol spec live in the companion
[Rolki-Server](https://github.com/smolBitness/Rolki-Server) repository.

## What it does

1. Watches PC/SC for a card. Which reader counts can be narrowed with
   `reader_filter`.
2. If more than one interpretation of the card is possible -- a
   dual-applet card, or TOTP labels configured -- a desktop popup asks
   the seat what this ceremony is for: gate passkeys, or reveal a TOTP
   code. Ignored popups time out to the gate.
3. Runs the gate ceremony against the server: fetch a fresh nonce,
   prompt for the card PIN on a tty, have the card's PIV 9A key sign the
   nonce, submit `{nonce, signature, cert}` over mTLS.
4. **On a pass with the gate action:** creates a virtual FIDO2 device on
   `/dev/uhid`. Browsers talk to it like any platform authenticator; the
   bridge forwards every CTAP2 frame verbatim to the server
   (`POST /ctap`). No card I/O happens during this live phase.
5. **On a pass with a TOTP action:** fetches the current code from the
   server and shows it as a desktop notification, valid until the end of
   its 30-second window. No device is created; the bridge then parks
   until the card state changes. Failures (refusal, unreachable server)
   are surfaced as notifications too, not silently swallowed.
6. On idle, max lifetime, card removal, error, or shutdown: destroys the
   device. On a failed or unreachable gate: never creates one.

The card is only touched during the ceremony. Everything after that is a
relay between the kernel's UHID interface and the server.

## Configuration

TOML, `~/.config/piv-gate/config.toml` by default. Connection fields
(`server_url`, `ca_root`, `client_cert`, `client_key`) are required; the
rest default as follows:

| Key | Default | Meaning |
|---|---|---|
| `t_idle` | `10m` | No CTAPHID traffic for this long -> teardown. |
| `t_max` | `12h` | Hard ceiling on a device since the gate pass. |
| `http_timeout` | `10s` | Per-request server timeout. |
| `retries` | `3` | Challenge-fetch retries. |
| `reader_filter` | unset | Substring match to pick one PC/SC reader. |
| `audit_log` | `~/.local/state/piv-gate/audit.jsonl` | Local event log (labels/events, never codes or PINs). |
| `prompt_on_ambiguous` | `true` | Show the seat picker when a card could mean more than one thing. |
| `prompt_timeout` | `20s` | Picker idle timeout; defaults to the gate action. |
| `totp_labels` | `[]` | Enrolled TOTP labels offered in the picker. Empty disables the whole path. |

## Run

```sh
poetry install
poetry run piv-gate-bridge --config ~/.config/piv-gate/config.toml
```

or via the provided user-level `piv-gate-bridge.service`
(`systemctl --user start piv-gate-bridge`). Tests:

```sh
python3 -m unittest discover -s tests -t .
```

`tools/e2e_fido2_client.py` is a no-hardware FIDO2 end-to-end client that
drives the virtual device exactly as a browser would (also mirrored in
Rolki-Client).

License: MIT (upstream, Bryan Jacobs -- see `LICENSE`).

