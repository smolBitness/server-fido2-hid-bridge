#!/usr/bin/env python3
"""No-hardware FIDO e2e.

Drives the bridge's virtual UHID device with python-fido2's
Fido2Client, exactly as a browser would:

  1. getInfo            (via INIT/CBOR)
  2. makeCredential     (fmt "none", UV flag, signCount 0, AAGUID)
  3. getAssertion       (verify the assertion signature against the
                         credential public key, the way an RP would)

Negatives: empty allowList -> CTAP2 0x2E, unknown command -> 0x01.

Run: python3 tools/e2e_fido2_client.py [--origin https://rp.example]
"""

import argparse
import hashlib
import sys

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialType,
)
from fido2 import cbor


def fail(msg):
    print(f"E2E FAIL: {msg}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://rp.example")
    parser.add_argument("--rp-id", default="rp.example")
    args = parser.parse_args()

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        fail("no CTAPHID device found (is the bridge live?)")
    client = Fido2Client(devices[0], args.origin)
    print(f"opened {devices[0]}")

    # -- makeCredential ------------------------------------------------------
    # NOTE: we deliberately do NOT pass user_verification="required" to
    # python-fido2: with no pinUvAuthProtocols advertised it insists on
    # constructing a ClientPin token flow for UV (fido2 1.2.0 limitation),
    # while this bridge's UV model is server-side internal UV (UV = gate
    # pass).  We assert the UV flag on the RESPONSE authData below, which
    # is the RP-visible guarantee.
    challenge = hashlib.sha256(b"registration-challenge").digest()
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id=args.rp_id, name="RP"),
        user=PublicKeyCredentialUserEntity(id=b"e2e-user-1", name="e2e"),
        challenge=challenge,
        pub_key_cred_params=[PublicKeyCredentialParameters(
            type="public-key", alg=-7)],
    )
    att = client.make_credential(options)
    print("makeCredential OK")

    att_obj = cbor.decode(att.attestation_object)
    if att_obj["fmt"] != "none":
        fail(f"fmt {att_obj['fmt']!r}, want 'none'")
    if att_obj["attStmt"] != {}:
        fail("attStmt not empty")
    auth_data = att_obj["authData"]
    from fido2.webauthn import AuthenticatorData
    ad = auth_data if isinstance(auth_data, AuthenticatorData) \
        else AuthenticatorData(bytes(auth_data))
    if not ad.is_user_verified() or not ad.is_user_present():
        fail("UP/UV flags missing")
    if ad.counter != 0:
        fail(f"signCount {ad.counter}, want 0")
    if bytes(ad.credential_data.aaguid) != bytes.fromhex(
            "4f7a6d319d1e4c8fa5b32f4e6d8c0a17"):
        fail(f"AAGUID {bytes(ad.credential_data.aaguid).hex()}")
    cred_id = bytes(ad.credential_data.credential_id)
    cred_pub = ad.credential_data.public_key
    print(f"  credential {cred_id.hex()[:24]}... ({len(cred_id)}B)")

    # -- getAssertion ----------------------------------------------------------
    challenge2 = hashlib.sha256(b"authentication-challenge").digest()
    options2 = PublicKeyCredentialRequestOptions(
        rp_id=args.rp_id,
        challenge=challenge2,
        allow_credentials=[PublicKeyCredentialDescriptor(
            type="public-key", id=cred_id)],
        # Same ClientPin-token limitation as above: no library-level UV.
    )
    assertion = client.get_assertion(options2).get_response(0)
    print("getAssertion OK")

    # Verify exactly as the RP would: sig over authData || clientDataHash (W3C §7.2).
    cdh = hashlib.sha256(assertion.client_data).digest()
    cred_pub.verify(bytes(assertion.authenticator_data) + cdh,
                    assertion.signature)
    print("assertion signature VERIFIES with the registered public key")

    # -- negatives (raw CTAP2 via CtapDevice call) -----------------------------
    from fido2.ctap2 import Ctap2
    from fido2.ctap import CtapError  # 1.2.x: CtapError lives in fido2.ctap
    c2 = Ctap2(devices[0])

    # empty allowList -> 0x2E NO_CREDENTIALS
    try:
        c2.get_assertion(args.rp_id, challenge2, allow_list=[])
        fail("empty allowList did not fail")
    except CtapError as exc:
        if exc.code != 0x2E:
            fail(f"empty allowList: expected 0x2E, got 0x{exc.code:02X}")
        print("empty allowList -> 0x2E OK")

    # unknown command -> CTAPHID ERROR 0x01 (call() ORs 0x80 and turns an
    # ERROR reply into CtapError(<error byte>))
    try:
        devices[0].call(0x99, b"")
        fail("unknown command did not fail")
    except CtapError as exc:
        if exc.code != 0x01:
            fail(f"unknown cmd: expected ERROR 0x01, got 0x{exc.code:02X}")
        print("unknown command -> ERROR 0x01 OK")

    print("E2E PASS")


if __name__ == "__main__":
    main()