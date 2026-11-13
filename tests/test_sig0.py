"""SIG(0) with ECDSA P-256 (RFC 2931, RFC 6605 section 4, RFC 9665 section 6.6).

The independent vector is RFC 6605 section 6.1: a P-256 DNSKEY, the private key that goes with it
and an RRSIG over ``www.example.net. A``. That signature is over RFC 4034 signing data, not a
SIG(0) message, so it proves the *primitive* (key and signature encodings, hash, curve) and not the
SIG(0) construction; the SIG(0) construction tests use signatures made here and say so. The RRSIG
signing data is built by hand in :func:`rfc6605_signed_data` from the RFC 4034 layout.
"""

from __future__ import annotations

import base64
import datetime
import struct

import pytest

from dnssd_srp.sig0 import (
    ALGORITHM_ECDSAP256SHA256,
    Sig0Error,
    SigningKey,
    VerifyKey,
    sign,
    signed_data,
    verify,
    within_validity,
)

pytest.importorskip("cryptography", reason="the crypto extra is not installed")

DNSKEY = base64.b64decode(
    "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)
PRIVATE = base64.b64decode("GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=")
RRSIG = base64.b64decode(
    "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="
)


def _epoch(stamp: str) -> int:
    parsed = datetime.datetime.strptime(stamp, "%Y%m%d%H%M%S").replace(tzinfo=datetime.UTC)
    return int(parsed.timestamp())


def _wire_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"


def rfc6605_signed_data() -> bytes:
    """RFC 4034 section 6: RRSIG RDATA without the signature, then the canonical RR."""
    rdata = struct.pack(
        "!HBBIIIH",
        1,  # type covered: A
        13,  # algorithm
        3,  # labels in www.example.net
        3600,
        _epoch("20100909100439"),
        _epoch("20100812100439"),
        55648,
    ) + _wire_name("example.net.")
    record = (
        _wire_name("www.example.net.") + struct.pack("!HHIH", 1, 1, 3600, 4) + bytes([192, 0, 2, 1])
    )
    return rdata + record


VERIFY_KEY = VerifyKey(ALGORITHM_ECDSAP256SHA256, DNSKEY)
SIGNING_KEY = SigningKey(ALGORITHM_ECDSAP256SHA256, PRIVATE)


def test_verify_rfc6605_p256_rrsig_vector():
    assert verify(rfc6605_signed_data(), RRSIG, VERIFY_KEY) is True


def test_rfc6605_private_key_belongs_to_the_published_dnskey():
    # Signatures are randomised, so the RFC's cannot be reproduced; verifying ours with the RFC's
    # public key is the check that the scalar loads and pairs with the DNSKEY.
    message = signed_data(b"rdata-without-signature", b"request message")
    assert verify(message, sign(message, SIGNING_KEY), VERIFY_KEY) is True


def test_flipped_bit_in_message_rejected():
    data = bytearray(rfc6605_signed_data())
    data[-1] ^= 1
    assert verify(bytes(data), RRSIG, VERIFY_KEY) is False


def test_flipped_bit_in_signature_rejected():
    bad = bytearray(RRSIG)
    bad[10] ^= 0x01
    assert verify(rfc6605_signed_data(), bytes(bad), VERIFY_KEY) is False


@pytest.mark.parametrize("size", [0, 63, 65, 72])
def test_signature_wrong_length_rejected(size):
    assert verify(b"m", bytes(size), VERIFY_KEY) is False


def test_der_signature_is_not_a_dns_signature():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.hashes import SHA256

    private = ec.derive_private_key(int.from_bytes(PRIVATE, "big"), ec.SECP256R1())
    der = private.sign(b"m", ec.ECDSA(SHA256()))
    assert verify(b"m", der, VERIFY_KEY) is False


def test_r_or_s_zero_or_ge_order_rejected():
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    good_s = RRSIG[32:]
    for r in (0, order, order + 1):
        assert verify(b"m", r.to_bytes(32, "big") + good_s, VERIFY_KEY) is False
    for s in (0, order):
        assert verify(b"m", RRSIG[:32] + s.to_bytes(32, "big"), VERIFY_KEY) is False


@pytest.mark.parametrize("algorithm", [5, 7, 8, 12, 14, 15, 16])
def test_unsupported_algorithm_refused_not_true(algorithm):
    with pytest.raises(Sig0Error, match="not implemented"):
        verify(b"m", bytes(64), VerifyKey(algorithm, DNSKEY))
    with pytest.raises(Sig0Error, match="not implemented"):
        SigningKey(algorithm, PRIVATE)


def test_a_key_off_the_curve_is_a_bad_key_not_a_forgery():
    with pytest.raises(Sig0Error, match="unusable key"):
        verify(b"m", RRSIG, VerifyKey(13, bytes(64)))
    with pytest.raises(Sig0Error):
        verify(b"m", RRSIG, VerifyKey(13, DNSKEY[:-1]))


def test_signing_key_rejects_bad_scalars():
    with pytest.raises(Sig0Error, match="octets"):
        SigningKey(13, bytes(31))
    with pytest.raises(Sig0Error, match="zero"):
        SigningKey(13, bytes(32))


def test_signed_data_is_rdata_then_request_in_that_order():
    # RFC 2931 section 3.1 paragraph 3: data = RDATA | request - SIG(0).
    assert signed_data(b"AAAA", b"BBBB") == b"AAAABBBB"
    assert signed_data(b"ab", b"cd") != signed_data(b"cd", b"ab")


def test_signature_does_not_cover_a_different_request():
    rdata = b"sig rdata"
    signature = sign(signed_data(rdata, b"request one"), SIGNING_KEY)
    assert verify(signed_data(rdata, b"request one"), signature, VERIFY_KEY) is True
    assert verify(signed_data(rdata, b"request two"), signature, VERIFY_KEY) is False
    assert verify(signed_data(b"other rdata", b"request one"), signature, VERIFY_KEY) is False


def test_expired_and_not_yet_valid_rejected_with_clock_argument():
    now = 1_000_000
    assert within_validity(now - 100, now + 100, now) is True
    assert within_validity(now + 1, now + 100, now) is False  # not yet valid
    assert within_validity(now - 100, now - 1, now) is False  # expired
    assert within_validity(now + 5, now, now) is False  # inception after expiration


def test_validity_bracket_wider_than_five_minutes_is_refused_and_configurable():
    now = 1_000_000
    assert within_validity(now - 300, now + 300, now) is True
    assert within_validity(now - 301, now + 100, now) is False
    assert within_validity(now - 100, now + 301, now) is False
    assert within_validity(now - 301, now + 301, now, skew=600) is True


def test_sign_without_the_backend_names_what_to_install(monkeypatch):
    import importlib

    from namespy.crypto import MissingCryptoError

    real = importlib.import_module

    def refuse(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real(name, *args, **kwargs)

    monkeypatch.setattr("dnssd_srp.sig0.importlib.import_module", refuse)
    with pytest.raises(MissingCryptoError, match="dnssd-srp"):
        sign(b"m", SIGNING_KEY)
