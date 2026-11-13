"""The Update Lease option (RFC 9664 section 4).

RFC 9664 publishes no wire vector. The bytes here are derived by hand from the Table 1 layout:
OPTION-CODE 2, OPTION-LENGTH 4 or 8, then LEASE (and KEY-LEASE) as big-endian 32-bit seconds.
"""

from __future__ import annotations

import pytest

from dnssd_srp.lease import (
    UPDATE_LEASE_OPTION_CODE,
    LeaseError,
    UpdateLease,
    decode_update_lease,
    encode_update_lease,
    from_edns_options,
    response_variant,
    to_edns_option,
)

TWO_HOURS = 7200
FOURTEEN_DAYS = 1209600


def test_four_byte_form_bytes():
    wire = encode_update_lease(UpdateLease(TWO_HOURS))
    assert wire == bytes.fromhex("0002 0004 00001c20")
    assert decode_update_lease(wire) == UpdateLease(TWO_HOURS)


def test_eight_byte_form_bytes():
    wire = encode_update_lease(UpdateLease(TWO_HOURS, FOURTEEN_DAYS))
    assert wire == bytes.fromhex("0002 0008 00001c20 00127500")
    assert decode_update_lease(wire) == UpdateLease(TWO_HOURS, FOURTEEN_DAYS)


@pytest.mark.parametrize("length", [0, 1, 3, 5, 7, 9, 12])
def test_decode_rejects_length_other_than_4_or_8(length):
    wire = bytes.fromhex("0002") + length.to_bytes(2, "big") + bytes(length)
    with pytest.raises(LeaseError, match="neither 4 nor 8"):
        decode_update_lease(wire)


def test_decode_rejects_wrong_option_code():
    with pytest.raises(LeaseError, match="not UPDATE-LEASE"):
        decode_update_lease(bytes.fromhex("0003 0004 00001c20"))


def test_decode_rejects_declared_length_beyond_buffer():
    with pytest.raises(LeaseError, match="runs past"):
        decode_update_lease(bytes.fromhex("0002 0008 00001c20"))


def test_decode_rejects_trailing_octets_and_short_headers():
    with pytest.raises(LeaseError, match="follow the option"):
        decode_update_lease(bytes.fromhex("0002 0004 00001c20 ff"))
    for size in range(4):
        with pytest.raises(LeaseError, match="shorter"):
            decode_update_lease(bytes(size))


def test_four_byte_key_lease_equals_lease():
    decoded = decode_update_lease(bytes.fromhex("0002 0004 00000e10"))
    assert decoded.key_lease is None
    assert decoded.effective_key_lease == 3600
    assert UpdateLease(10, 99).effective_key_lease == 99


def test_u32_bounds():
    for value in (0, 0xFFFFFFFF):
        assert decode_update_lease(encode_update_lease(UpdateLease(value, value))) == UpdateLease(
            value, value
        )
    for bad in (2**32, -1):
        with pytest.raises(LeaseError, match="LEASE"):
            UpdateLease(bad)
        with pytest.raises(LeaseError, match="KEY-LEASE"):
            UpdateLease(1, bad)


def test_lease_greater_than_key_lease_flagged():
    # Well formed on the wire; a registrar's policy (RFC 9665 section 3.3.2 paragraph 2) says it
    # is "not an SRP Update".
    value = decode_update_lease(bytes.fromhex("0002 0008 00000010 00000005"))
    assert value == UpdateLease(16, 5)
    assert value.is_srp_valid() is False
    assert UpdateLease(5, 5).is_srp_valid() is True
    assert UpdateLease(5).is_srp_valid() is True


def test_server_answers_in_the_requesters_variant():
    # RFC 9664 section 4.3 paragraphs 3-4.
    eight = response_variant(UpdateLease(60, 600), 120, 1200)
    assert eight == UpdateLease(120, 1200)
    four = response_variant(UpdateLease(60), 120, 120)
    assert four == UpdateLease(120)
    assert encode_update_lease(four)[2:4] == bytes.fromhex("0004")
    with pytest.raises(LeaseError, match="4-byte"):
        response_variant(UpdateLease(60), 120, 1200)


def test_edns_option_roundtrip_through_the_shared_codec():
    from namespy.edns import parse_options, serialize_options

    value = UpdateLease(TWO_HOURS, FOURTEEN_DAYS)
    option = to_edns_option(value)
    assert option.code == UPDATE_LEASE_OPTION_CODE
    assert option.octets == encode_update_lease(value)
    parsed = parse_options(serialize_options([option]))
    assert from_edns_options(parsed) == value


def test_absent_option_is_none_not_a_default():
    from namespy.edns import EdnsOption

    assert from_edns_options([]) is None
    assert from_edns_options([EdnsOption(10, bytes(8))]) is None


def test_present_but_malformed_option_raises():
    from namespy.edns import EdnsOption

    with pytest.raises(LeaseError):
        from_edns_options([EdnsOption(UPDATE_LEASE_OPTION_CODE, bytes(6))])
