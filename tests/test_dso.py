"""DSO codec (RFC 8490 sections 5.4 and 7).

RFC 8490 publishes no wire vector, so the byte strings below were derived by hand from the
section 5.4 header figure (MESSAGE ID, then QR, OPCODE 6 in bits 14-11, seven Z bits, RCODE)
and the section 5.4.4 TLV figure, and checked once against them; they are not produced by the
code under test.
"""

from __future__ import annotations

import random

import pytest

from dnssd_srp.dso import (
    DSO_OPCODE,
    ENCRYPTION_PADDING,
    KEEPALIVE,
    RCODE_FORMERR,
    RETRY_DELAY,
    DsoError,
    DsoMessage,
    MessageKind,
    Tlv,
    decode_dso,
    encode_dso,
    keepalive_tlv,
    padding_tlv,
    parse_keepalive,
    parse_retry_delay,
    retry_delay_tlv,
)

# ID 0x1234, QR 0 OPCODE 6 -> 0x3000, four zero counts.
HEADER_REQUEST = bytes.fromhex("1234 3000 0000 0000 0000 0000")
# Keepalive TLV: type 1, length 8, INACTIVITY 15000 ms (0x3A98), INTERVAL 15000 ms.
KEEPALIVE_TLV = bytes.fromhex("0001 0008 00003a98 00003a98")


def test_header_is_twelve_bytes_opcode_six():
    message = DsoMessage(0x1234, False, tlvs=(keepalive_tlv(15000, 15000),))
    wire = encode_dso(message)
    assert wire == HEADER_REQUEST + KEEPALIVE_TLV
    assert len(wire[:12]) == 12
    assert (wire[2] >> 3) & 0xF == DSO_OPCODE == 6


def test_response_sets_qr_and_carries_rcode():
    wire = encode_dso(DsoMessage(7, True, rcode=11))
    assert wire == bytes.fromhex("0007 b00b 0000 0000 0000 0000")


def test_roundtrip_all_three_base_tlvs():
    message = DsoMessage(
        42, False, tlvs=(keepalive_tlv(30000, 20000), retry_delay_tlv(5000), padding_tlv(6))
    )
    again = decode_dso(encode_dso(message))
    assert again == message
    assert [t.dso_type for t in again.tlvs] == [KEEPALIVE, RETRY_DELAY, ENCRYPTION_PADDING]
    assert parse_keepalive(again.tlvs[0]) == (30000, 20000)
    assert parse_retry_delay(again.tlvs[1]) == 5000


@pytest.mark.parametrize("count_index", [0, 1, 2, 3])
def test_decode_rejects_nonzero_counts(count_index):
    raw = bytearray(HEADER_REQUEST + KEEPALIVE_TLV)
    raw[5 + 2 * count_index] = 1
    with pytest.raises(DsoError) as caught:
        decode_dso(bytes(raw))
    assert caught.value.rcode == RCODE_FORMERR
    assert caught.value.fatal is False


def test_decode_rejects_wrong_opcode():
    raw = bytes.fromhex("1234 0000 0000 0000 0000 0000") + KEEPALIVE_TLV  # OPCODE 0
    with pytest.raises(DsoError, match="OPCODE"):
        decode_dso(raw)


@pytest.mark.parametrize("size", [0, 1, 11])
def test_decode_rejects_a_message_shorter_than_the_header(size):
    with pytest.raises(DsoError, match="shorter"):
        decode_dso(HEADER_REQUEST[:size])


@pytest.mark.parametrize("extra", [1, 2, 3])
def test_decode_rejects_truncated_tlv_header(extra):
    with pytest.raises(DsoError, match="stray"):
        decode_dso(HEADER_REQUEST + KEEPALIVE_TLV + b"\x00" * extra)


def test_decode_rejects_length_overrun():
    raw = HEADER_REQUEST + bytes.fromhex("0009 ffff 0102")
    with pytest.raises(DsoError, match="declares 65535"):
        decode_dso(raw)


def test_request_with_zero_tlvs_refused_both_ways():
    with pytest.raises(DsoError, match="no TLV"):
        decode_dso(HEADER_REQUEST)
    with pytest.raises(DsoError, match="at least one TLV"):
        encode_dso(DsoMessage(1, False))
    with pytest.raises(DsoError, match="at least one TLV"):
        encode_dso(DsoMessage(0, False))


def test_a_response_may_carry_no_tlvs():
    # RFC 8490 section 5.4.2 paragraph 4: "A DSO response message may contain no TLVs".
    message = decode_dso(bytes.fromhex("0005 b000 0000 0000 0000 0000"))
    assert message.kind is MessageKind.RESPONSE
    assert message.tlvs == ()


def test_unidirectional_and_request_distinguished_by_id():
    assert DsoMessage(0, False, tlvs=(Tlv(1),)).kind is MessageKind.UNIDIRECTIONAL
    assert DsoMessage(1, False, tlvs=(Tlv(1),)).kind is MessageKind.REQUEST
    assert DsoMessage(1, True).kind is MessageKind.RESPONSE
    assert decode_dso(encode_dso(DsoMessage(0, False, tlvs=(Tlv(1),)))).kind is (
        MessageKind.UNIDIRECTIONAL
    )


def test_response_with_zero_id_is_fatal():
    with pytest.raises(DsoError) as caught:
        decode_dso(bytes.fromhex("0000 b000 0000 0000 0000 0000"))
    assert caught.value.fatal is True
    with pytest.raises(DsoError) as sent:
        encode_dso(DsoMessage(0, True))
    assert sent.value.fatal is True


def test_codec_does_not_judge_a_keepalive_sent_unidirectionally():
    # Section 5.4.1 paragraph 2: whether a Keepalive may be unidirectional is the session's call.
    message = decode_dso(encode_dso(DsoMessage(0, False, tlvs=(keepalive_tlv(15000, 15000),))))
    assert message.kind is MessageKind.UNIDIRECTIONAL
    assert message.primary is not None
    assert message.primary.dso_type == KEEPALIVE


def test_keepalive_interval_below_ten_seconds_refused_on_parse_and_build():
    with pytest.raises(ValueError, match="10000"):
        keepalive_tlv(15000, 9999)
    short = Tlv(KEEPALIVE, bytes.fromhex("00003a98 0000270f"))
    with pytest.raises(DsoError, match="10000"):
        parse_keepalive(short)
    assert parse_keepalive(Tlv(KEEPALIVE, bytes.fromhex("00003a98 00002710"))) == (15000, 10000)


@pytest.mark.parametrize("size", [0, 4, 7, 9])
def test_keepalive_and_retry_delay_bodies_have_fixed_sizes(size):
    with pytest.raises(DsoError):
        parse_keepalive(Tlv(KEEPALIVE, bytes(size)))
    if size != 4:
        with pytest.raises(DsoError):
            parse_retry_delay(Tlv(RETRY_DELAY, bytes(size)))


def test_parsers_refuse_the_wrong_type():
    with pytest.raises(DsoError, match="not Keepalive"):
        parse_keepalive(Tlv(RETRY_DELAY, bytes(8)))
    with pytest.raises(DsoError, match="not Retry Delay"):
        parse_retry_delay(Tlv(KEEPALIVE, bytes(4)))


def test_unknown_tlv_type_preserved_in_order():
    tlvs = (
        Tlv(0x0040, b"abc"),
        Tlv(0xF800, b""),
        keepalive_tlv(15000, 15000),
        Tlv(0xFFFF, b"\x01"),
    )
    again = decode_dso(encode_dso(DsoMessage(9, False, tlvs=tlvs)))
    assert again.tlvs == tlvs


def test_type_zero_is_reserved_so_never_sent_but_kept_when_received():
    with pytest.raises(DsoError, match="reserved"):
        encode_dso(DsoMessage(1, False, tlvs=(Tlv(0, b""),)))
    received = decode_dso(HEADER_REQUEST + bytes.fromhex("0000 0001 ff"))
    assert received.tlvs == (Tlv(0, b"\xff"),)


def test_z_bits_ignored_on_decode_zero_on_encode():
    raw = bytearray(HEADER_REQUEST + KEEPALIVE_TLV)
    raw[2] |= 0x07  # three of the Z bits
    raw[3] |= 0xF0  # four more
    message = decode_dso(bytes(raw))
    assert message.rcode == 0
    assert encode_dso(message) == HEADER_REQUEST + KEEPALIVE_TLV


def test_padding_of_any_value_is_accepted_and_zero_length_is_legal():
    assert padding_tlv(0) == Tlv(ENCRYPTION_PADDING, b"")
    assert padding_tlv(3, fill=0xAB).data == b"\xab\xab\xab"
    message = decode_dso(HEADER_REQUEST + bytes.fromhex("0003 0004 deadbeef"))
    assert message.tlvs[0].data == b"\xde\xad\xbe\xef"
    with pytest.raises(ValueError, match="padding"):
        padding_tlv(65536)


def test_u32_bounds():
    assert parse_retry_delay(retry_delay_tlv(0xFFFFFFFF)) == 0xFFFFFFFF
    with pytest.raises(ValueError, match="retry delay"):
        retry_delay_tlv(2**32)
    with pytest.raises(ValueError, match="retry delay"):
        retry_delay_tlv(-1)


def test_message_and_tlv_field_ranges():
    with pytest.raises(ValueError, match="MESSAGE ID"):
        DsoMessage(65536, False)
    with pytest.raises(ValueError, match="RCODE"):
        DsoMessage(1, True, rcode=16)
    with pytest.raises(ValueError, match="DSO-TYPE"):
        Tlv(65536)
    with pytest.raises(ValueError, match="DSO-DATA"):
        Tlv(1, bytes(65536))


def test_decode_never_returns_garbage_on_random_bytes():
    rng = random.Random(8490)
    for _ in range(2000):
        size = rng.randrange(0, 40)
        blob = bytes(rng.randrange(256) for _ in range(size))
        if rng.random() < 0.7 and size >= 12:  # bias toward the DSO header so TLV paths run
            blob = blob[:2] + bytes([0x30 | (blob[2] & 0x87), blob[3]]) + bytes(8) + blob[12:]
        try:
            message = decode_dso(blob)
        except DsoError:
            continue
        # Whatever decodes must re-encode to the same TLV bytes (Z bits aside); type 0 is the
        # one thing decode keeps and encode refuses.
        if any(t.dso_type == 0 for t in message.tlvs):
            continue
        assert not (message.qr and message.message_id == 0)
        assert encode_dso(message)[12:] == blob[12:]
