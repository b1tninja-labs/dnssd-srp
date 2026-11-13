"""The SIG(0) record and its place in a message (RFC 2931 section 3, RFC 2535 section 4.1).

The key is RFC 6605 section 6.1's P-256 pair, so the primitive is the one the RFC publishes a
vector for; the signatures here are made by this module, because RFC 2931 prints no SIG(0) with
bytes. What the tests pin is the construction: the signed data, the record's header fields, its
position, and what a verifier does to a message that was altered after signing.
"""

from __future__ import annotations

import base64
import struct

import pytest
from namespy.enums import DnsOpCode, DnsQType, DnsRClass, DnsRType
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord
from namespy.rdata import RData_SIG

from dnssd_srp.sig0 import (
    ALGORITHM_ECDSAP256SHA256,
    SigningKey,
    VerifyKey,
    key_rr,
    sign_request,
    signed_data,
    split_sig0,
    verify_request,
)

pytest.importorskip("cryptography", reason="the crypto extra is not installed")

DNSKEY = base64.b64decode(
    "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)
PRIVATE = base64.b64decode("GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=")
SIGNING = SigningKey(ALGORITHM_ECDSAP256SHA256, PRIVATE)
VERIFYING = VerifyKey(ALGORITHM_ECDSAP256SHA256, DNSKEY)
NOW = 1_700_000_000
SIGNER = "host.default.service.arpa."


def _request(with_opt: bool = True) -> bytes:
    packet = DnsPacket(
        0x1234,
        OPCODE=DnsOpCode.UPDATE,
        RD=False,
        questions=[DnsQuestion("default.service.arpa.", DnsQType.SOA, DnsRClass.IN)],
        nameservers=[DnsRecord("host.default.service.arpa.", DnsRType.A, 1, 120, rdata=bytes(4))],
    )
    if with_opt:
        packet.add_edns()
    return bytes(packet)


def _signed(request: bytes | None = None) -> bytes:
    key = key_rr(DNSKEY)
    return sign_request(
        request if request is not None else _request(),
        SIGNING,
        signer=SIGNER,
        key_tag=key.key_tag,
        now=NOW,
    )


def test_sig0_rr_layout() -> None:
    message = _signed()
    parts = split_sig0(message)
    assert parts is not None
    record, sig = parts.record, parts.sig
    assert str(record.name) == "."  # RFC 2931 section 3 paragraph 3: root owner
    assert int(record.rclass) == int(DnsRClass.ANY)  # ... class ANY
    assert record.ttl == 0  # ... TTL zero
    assert int(record.rtype) == int(DnsRType.SIG)
    assert (sig.type_covered, sig.labels, sig.original_ttl) == (0, 0, 0)  # section 3.1 paragraph 1
    assert sig.algorithm == 13
    assert (sig.inception, sig.expiration) == (NOW - 60, NOW + 240)
    assert str(sig.signer_name) == SIGNER
    assert sig.key_tag == key_rr(DNSKEY).key_tag
    assert len(sig.signature) == 64
    assert isinstance(sig, RData_SIG)


def test_the_sig0_is_last_and_arcount_counts_it() -> None:
    request = _request()
    message = _signed(request)
    assert struct.unpack_from("!H", message, 10)[0] == struct.unpack_from("!H", request, 10)[0] + 1
    packet, _ = DnsPacket.parse(message)
    assert int(packet.additional_records[-1].rtype) == int(DnsRType.SIG)
    assert int(packet.additional_records[0].rtype) == int(DnsRType.OPT)  # OPT stays ahead


def test_split_returns_the_request_as_it_was_signed() -> None:
    request = _request()
    parts = split_sig0(_signed(request))
    assert parts is not None
    assert parts.request == request  # ARCOUNT back to what it was, no SIG(0) octets


def test_signature_is_over_rdata_then_the_unadjusted_request() -> None:
    """RFC 2931 section 3.1 paragraph 3: data = RDATA | request - SIG(0)."""
    request = _request()
    parts = split_sig0(_signed(request))
    assert parts is not None
    data = signed_data(parts.sig.rdata_without_signature(), request)
    from dnssd_srp.sig0 import verify

    assert verify(data, parts.sig.signature, VERIFYING)
    # The same data with the counts adjusted (the wrong request form) must not verify.
    adjusted = request[:10] + struct.pack("!H", struct.unpack_from("!H", request, 10)[0] + 1)
    adjusted += request[12:]
    wrong = signed_data(parts.sig.rdata_without_signature(), adjusted)
    assert not verify(wrong, parts.sig.signature, VERIFYING)


def test_a_signed_request_verifies_inside_its_lifetime() -> None:
    assert verify_request(_signed(), VERIFYING, now=NOW)
    assert verify_request(_signed(), VERIFYING, now=NOW + 200)


@pytest.mark.parametrize("offset", [0, 3, 12, 20, 40])
def test_a_flipped_bit_anywhere_in_the_request_fails(offset: int) -> None:
    message = bytearray(_signed())
    message[offset] ^= 0x01
    assert not verify_request(bytes(message), VERIFYING, now=NOW)


def test_the_wrong_key_fails() -> None:
    other = SigningKey(ALGORITHM_ECDSAP256SHA256, bytes([1] * 31 + [2]))
    message = sign_request(_request(), other, signer=SIGNER, key_tag=1, now=NOW)
    assert not verify_request(message, VERIFYING, now=NOW)


def test_outside_the_lifetime_fails() -> None:
    message = _signed()
    assert not verify_request(message, VERIFYING, now=NOW + 241 + 60)  # expired
    assert not verify_request(message, VERIFYING, now=NOW - 61)  # not yet valid


def test_a_message_with_no_sig0_does_not_verify_and_does_not_split() -> None:
    assert split_sig0(_request()) is None
    assert not verify_request(_request(), VERIFYING, now=NOW)
    assert split_sig0(b"") is None


def test_a_sig_that_covers_a_type_is_not_a_sig0() -> None:
    sig = RData_SIG(1, 13, 3, 60, NOW + 10, NOW - 10, 7, SIGNER, b"\x01" * 64)
    record = DnsRecord(".", DnsRType.SIG, DnsRClass.ANY, 0, rdata=sig)
    packet = DnsPacket(1, OPCODE=DnsOpCode.UPDATE, RD=False, additional_records=[record])
    assert split_sig0(bytes(packet)) is None


def test_trailing_octets_after_the_sig0_mean_it_is_not_last() -> None:
    assert split_sig0(_signed() + b"\x00") is None


def test_an_algorithm_mismatch_between_sig_and_key_fails_closed() -> None:
    other = VerifyKey(8, DNSKEY)
    assert not verify_request(_signed(), other, now=NOW)


def test_key_rr_has_zero_flags_and_protocol_three() -> None:
    """RFC 9665 section 3.2.5.1 paragraph 5: the KEY flags are all zero."""
    key = key_rr(DNSKEY)
    assert (key.flags, key.protocol, key.algorithm) == (0, 3, 13)
    assert key.public_key == DNSKEY


def test_signing_refuses_a_bracket_that_does_not_fit() -> None:
    from dnssd_srp.sig0 import Sig0Error

    with pytest.raises(Sig0Error, match="bracket"):
        sign_request(_request(), SIGNING, signer=SIGNER, key_tag=1, now=10)
