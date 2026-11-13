"""SRP update construction, reading and classification (RFC 9665 section 3, RFC 2136 section 2).

RFC 9665 prints no message with bytes, so the expectations are the instruction shapes of
sections 3.2.5 and 3.3.1 read from the text; every classification test names the paragraph.
Signatures are made by this package with RFC 6605 section 6.1's P-256 key.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import replace

import pytest
from namespy.enums import DnsOpCode, DnsQType, DnsRType
from namespy.packet import DnsPacket
from namespy.rdata import type_name_of

from dnssd_srp.lease import UpdateLease
from dnssd_srp.model import OpKind, UpdateMessage, UpdateOp
from dnssd_srp.registrar import (
    RCODE_NOERROR,
    RCODE_REFUSED,
    RCODE_YXDOMAIN,
    NotSrp,
    SrpUpdate,
    check_fcfs,
    check_signature,
    classify_update,
)
from dnssd_srp.sig0 import ALGORITHM_ECDSAP256SHA256, SigningKey, key_rr
from dnssd_srp.srp import ServiceDefinition, SrpFormatError, build_update, update_message

pytest.importorskip("cryptography", reason="the crypto extra is not installed")

PUBLIC = base64.b64decode(
    "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)
PRIVATE = base64.b64decode("GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=")
SIGNING = SigningKey(ALGORITHM_ECDSAP256SHA256, PRIVATE)
ZONE = "default.service.arpa."
HOST = "host.default.service.arpa."
INSTANCE = "Printer._ipp._tcp.default.service.arpa."
SERVICE = "_ipp._tcp.default.service.arpa."
LEASE = UpdateLease(7200, 1209600)
NOW = 1_700_000_000
SV = ServiceDefinition(INSTANCE, SERVICE, 631, (b"txtvers=1",))


def _build(services=(SV,), addresses=("2001:db8::1", "192.0.2.1"), lease=LEASE, **kw) -> bytes:
    return build_update(
        ZONE, HOST, addresses, services, lease, SIGNING, PUBLIC, now=NOW, message_id=7, **kw
    )


def _message(raw: bytes | None = None) -> UpdateMessage:
    return update_message(DnsPacket.parse(raw or _build())[0])


def _srp(raw: bytes | None = None) -> SrpUpdate:
    result = classify_update(_message(raw))
    assert isinstance(result, SrpUpdate), result
    return result


# ----------------------------------------------------------------- the requester


def test_build_update() -> None:
    packet, _ = DnsPacket.parse(_build())
    assert int(packet.OPCODE) == int(DnsOpCode.UPDATE)
    assert packet.ID == 7
    assert [str(q.name) for q in packet.questions] == [ZONE]
    assert packet.answers == []  # no prerequisites (section 3.2.3 paragraph 4)
    assert int(packet.additional_records[-1].rtype) == int(DnsRType.SIG)


def test_update_message_round_trips_through_namespy() -> None:
    message = _message()
    assert message.zone == ZONE
    assert message.prerequisites == 0
    assert message.lease == LEASE
    kinds = [(op.kind, type_name_of(op.rrtype)) for op in message.ops]
    assert kinds == [
        (OpKind.ADD, "PTR"),
        (OpKind.DELETE_NAME, "TYPE255"),
        (OpKind.ADD, "SRV"),
        (OpKind.ADD, "TXT"),
        (OpKind.DELETE_NAME, "TYPE255"),
        (OpKind.ADD, "KEY"),
        (OpKind.ADD, "AAAA"),
        (OpKind.ADD, "A"),
    ]


def test_the_service_key_is_omitted_by_default_and_repeatable() -> None:
    default = _srp()
    assert default.services[0].key is None
    repeated = _srp(_build(repeat_service_keys=True))
    assert repeated.services[0].key == repeated.key


def test_key_flags_are_zero_and_every_rr_has_one_ttl() -> None:
    update = _srp()
    assert update.key.flags == 0  # section 3.2.5.1 paragraph 5
    ttls = {op.ttl for op in _message().ops if op.kind is OpKind.ADD}
    assert ttls == {120}


def test_a_removal_needs_lease_zero_and_keeps_the_key() -> None:
    with pytest.raises(ValueError, match="LEASE zero"):
        _build(services=(), addresses=())
    removal = _srp(_build(services=(), addresses=(), lease=UpdateLease(0, 0)))
    assert removal.removes_host
    assert removal.addresses == ()


def test_lease_above_key_lease_is_refused_at_build() -> None:
    with pytest.raises(ValueError, match="KEY-LEASE"):
        _build(lease=UpdateLease(100, 50))


def test_a_service_without_txt_is_refused_at_build() -> None:
    with pytest.raises(ValueError, match="TXT"):
        _build(services=(replace(SV, txt=()),))


# ------------------------------------------------------------------ the registrar


def test_a_requesters_update_classifies_as_an_srp_update() -> None:
    update = _srp()
    assert update.host == HOST.rstrip(".")
    assert [s.name for s in update.services] == [INSTANCE.rstrip(".").lower()]
    assert update.services[0].txt_count == 1
    assert update.services[0].srv is not None
    assert update.services[0].srv.port == 631
    assert [(d.service, d.add) for d in update.discovery] == [(SERVICE.rstrip("."), True)]
    assert len(update.addresses) == 2
    assert update.key.to_wire() == key_rr(PUBLIC).to_wire()


def _ops(**changes) -> UpdateMessage:
    return replace(_message(), **changes)


def _without(message: UpdateMessage, predicate) -> UpdateMessage:
    return replace(message, ops=tuple(op for op in message.ops if not predicate(op)))


def _reason(message: UpdateMessage) -> str:
    result = classify_update(message)
    assert isinstance(result, NotSrp)
    return result.reason


def test_two_host_descriptions_is_not_an_srp_update() -> None:
    """Section 3.3.2 paragraph 1: exactly one Host Description Instruction."""
    message = _message()
    other = [
        UpdateOp(OpKind.DELETE_NAME, "other.default.service.arpa.", int(DnsQType.ANY)),
        replace(
            next(o for o in message.ops if o.rrtype == int(DnsRType.KEY)),
            name="other.default.service.arpa.",
        ),
    ]
    assert "2 Host Description" in _reason(replace(message, ops=message.ops + tuple(other)))


def test_prerequisites_make_it_not_an_srp_update() -> None:
    """Section 3.3.2 paragraph 1."""
    assert "prerequisites" in _reason(_ops(prerequisites=1))


def test_no_lease_option_or_lease_above_key_lease_is_not_an_srp_update() -> None:
    """Section 3.3.2 paragraph 2."""
    assert "no Update Lease" in _reason(_ops(lease=None))
    assert "KEY-LEASE" in _reason(_ops(lease=UpdateLease(10, 5)))
    assert isinstance(classify_update(_ops(lease=UpdateLease(10))), SrpUpdate)  # 4-byte form


def test_a_name_outside_the_zone_is_not_an_srp_update() -> None:
    """Section 3.3.1 paragraph 4."""
    message = _message()
    moved = replace(message.ops[0], name="_ipp._tcp.elsewhere.example.")
    assert "outside the zone" in _reason(replace(message, ops=(moved, *message.ops[1:])))


def test_stray_add_for_an_unrelated_type_is_not_an_srp_update() -> None:
    message = _message()
    stray = UpdateOp(OpKind.ADD, HOST, int(DnsRType.MX), 120, b"\x00\x01\x00")
    assert "besides KEY, A and AAAA" in _reason(replace(message, ops=(*message.ops, stray)))


def test_host_needs_its_delete_all_and_key() -> None:
    """Section 3.3.1.3 paragraph 3."""
    message = _message()
    no_key = _without(
        message, lambda op: op.name.lower().startswith("host.") and op.rrtype == int(DnsRType.KEY)
    )
    assert "KEY add" in _reason(no_key)
    host_delete = [
        op for op in message.ops if op.name.startswith("host.") and op.kind is OpKind.DELETE_NAME
    ]
    assert "delete-all" in _reason(_without(message, lambda op: op in host_delete))


def test_delete_all_must_precede_the_adds_for_its_name() -> None:
    """Section 3.3.1 paragraph 3: the only ordering constraint."""
    message = _message()
    ops = list(message.ops)
    first = next(i for i, op in enumerate(ops) if op.kind is OpKind.DELETE_NAME)
    ops[first], ops[first + 1] = ops[first + 1], ops[first]  # SRV add before its delete-all
    assert "precedes the delete-all" in _reason(replace(message, ops=tuple(ops)))


def test_srv_target_must_be_the_host() -> None:
    """Section 3.3.1.2."""
    message = _message()
    ops = tuple(
        replace(op, rdata=op.rdata[:6] + b"\x05other\x00") if op.rrtype == int(DnsRType.SRV) else op
        for op in message.ops
    )
    assert "not the host name" in _reason(replace(message, ops=ops))


def test_srv_without_txt_and_txt_without_srv_are_refused() -> None:
    """Section 3.3.1.2: SRV and TXT come together."""
    message = _message()
    assert "together" in _reason(_without(message, lambda op: op.rrtype == int(DnsRType.TXT)))


def test_a_service_key_that_differs_from_the_host_key_is_refused() -> None:
    """Section 3.3.1.2: a present KEY MUST match the host's."""
    message = _message()
    other_key = key_rr(bytes(64)).to_wire()
    bad = UpdateOp(OpKind.ADD, INSTANCE, int(DnsRType.KEY), 120, other_key)
    ops = list(message.ops)
    at = next(i for i, op in enumerate(ops) if op.rrtype == int(DnsRType.TXT)) + 1
    ops.insert(at, bad)
    assert "differs from the host KEY" in _reason(replace(message, ops=tuple(ops)))


def test_ptr_add_for_an_instance_without_srv_is_refused() -> None:
    """Section 3.3.1.1: an add needs the SRV and TXT adds."""
    message = _message()
    ops = tuple(op for op in message.ops if op.rrtype not in (int(DnsRType.SRV), int(DnsRType.TXT)))
    # Without SRV the instance only has a delete-all; the PTR add then points at a deletion.
    assert "no SRV add" in _reason(replace(message, ops=ops))


def test_ptr_target_without_a_service_description_is_refused() -> None:
    message = _message()
    keep = tuple(op for op in message.ops if op.name.lower() != INSTANCE.lower())
    assert "no Service Description" in _reason(replace(message, ops=keep))


def test_deleting_a_service_pairs_a_ptr_delete_with_a_bare_delete_all() -> None:
    """Section 3.2.5.5.2 alternative 1 and section 3.3.1.1."""
    message = _message()
    ptr = next(op for op in message.ops if op.rrtype == int(DnsRType.PTR))
    ops = tuple(
        replace(op, kind=OpKind.DELETE_RR, ttl=0) if op is ptr else op
        for op in message.ops
        if op.rrtype not in (int(DnsRType.SRV), int(DnsRType.TXT))
    )
    update = classify_update(replace(message, ops=ops))
    assert isinstance(update, SrpUpdate)
    assert update.services[0].srv is None
    assert not update.discovery[0].add


def test_update_message_rejects_what_rfc2136_calls_formerr() -> None:
    packet, _ = DnsPacket.parse(_build())
    packet.OPCODE = DnsOpCode.QUERY
    with pytest.raises(SrpFormatError):
        update_message(packet)
    packet, _ = DnsPacket.parse(_build())
    packet.questions = []
    with pytest.raises(SrpFormatError):
        update_message(packet)


# ------------------------------------------------------- FCFS and the signature


def test_a_different_key_for_an_owned_name_is_yxdomain() -> None:
    """Section 3.3.3 paragraph 1."""
    update = _srp()
    other = key_rr(bytes(64)).to_wire()
    assert check_fcfs(update, {}) == RCODE_NOERROR
    assert check_fcfs(update, {HOST.lower().rstrip("."): update.key.to_wire()}) == RCODE_NOERROR
    assert check_fcfs(update, {HOST.lower().rstrip("."): other}) == RCODE_YXDOMAIN
    # An omitted service KEY inherits the host KEY, so a service owned by another key conflicts.
    assert check_fcfs(update, {INSTANCE.lower().rstrip("."): other}) == RCODE_YXDOMAIN
    assert check_fcfs(update, {INSTANCE.lower().rstrip("."): update.key.to_wire()}) == RCODE_NOERROR


def test_a_valid_signature_passes_and_a_tampered_update_is_refused() -> None:
    """Section 3.3.3 paragraph 2."""
    raw = _build()
    update = _srp(raw)
    assert check_signature(raw, update, now=NOW) == RCODE_NOERROR
    tampered = bytearray(raw)
    tampered[20] ^= 1
    assert check_signature(bytes(tampered), update, now=NOW) == RCODE_REFUSED
    assert check_signature(raw, update, now=NOW + 10_000) == RCODE_REFUSED


def test_a_key_of_another_algorithm_cannot_be_checked_and_is_refused() -> None:
    update = _srp()
    other = replace(update, key=key_rr(PUBLIC, algorithm=8))
    assert check_signature(_build(), other, now=NOW) == RCODE_REFUSED


def test_the_counts_in_the_header_still_describe_the_message() -> None:
    raw = _build()
    qd, an, ns, ar = struct.unpack_from("!4H", raw, 4)
    assert (qd, an) == (1, 0)
    assert ns == len(_message().ops)
    assert ar == 2  # OPT and the SIG(0)


# ------------------------------------------------------------- the whole pipeline


def _zone(keys=None):
    from dnssd_srp.registrar import ZoneContext

    return ZoneContext(ZONE, keys or {})


def test_validate_update_accepts_a_valid_update() -> None:
    from dnssd_srp.registrar import validate_update

    outcome = validate_update(_build(), _zone(), now=NOW)
    assert outcome.rcode == RCODE_NOERROR
    assert outcome.update is not None


def test_validate_update_maps_each_failure_to_the_rcode_the_rfc_names() -> None:
    from dnssd_srp.registrar import validate_update

    raw = _build()
    other = key_rr(bytes(64)).to_wire()
    owned = {HOST.lower().rstrip("."): other}
    assert validate_update(raw, _zone(owned), now=NOW).rcode == RCODE_YXDOMAIN
    assert validate_update(raw, _zone(), now=NOW + 10_000).rcode == RCODE_REFUSED
    assert validate_update(b"\x00" * 5, _zone(), now=NOW).rcode == 1  # FORMERR
    wrong_zone = validate_update(raw, replace(_zone(), origin="example.org."), now=NOW)
    assert wrong_zone.rcode == 10  # NOTZONE


def test_validate_update_refuses_what_is_not_an_srp_update() -> None:
    from dnssd_srp.registrar import validate_update

    packet, _ = DnsPacket.parse(_build())
    packet.add_edns()  # replaces the OPT: no Update Lease option any more
    unsigned = bytes(packet)
    outcome = validate_update(unsigned, _zone(), now=NOW)
    assert outcome.rcode == RCODE_REFUSED
    assert "Update Lease" in outcome.reason


def test_dso_header_is_the_shared_codecs() -> None:
    from namespy.enums import DnsOpCode as Op

    from dnssd_srp.dso import DSO_OPCODE, DsoMessage, Tlv, encode_dso

    raw = encode_dso(DsoMessage(5, False, tlvs=(Tlv(3, b""),)))
    header, _ = DnsPacket.parse(raw[:4] + bytes(8))
    assert int(header.OPCODE) == int(Op.DSO) == DSO_OPCODE
    assert header.ID == 5
