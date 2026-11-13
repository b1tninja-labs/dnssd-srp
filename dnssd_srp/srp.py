"""SRP update construction and reading (RFC 9665 sec. 3, RFC 2136 section 2).

An SRP Update is a DNS Update message built over namespy's :class:`namespy.packet.DnsPacket`,
not a second codec: the Zone section is the question section, the Prerequisite section is the
answer section (empty, RFC 9665 section 3.2.3 paragraph 4), the Update section is the authority
section, and the additional section holds the OPT record with the Update Lease option and, last,
the SIG(0) (RFC 2136 section 2.1, RFC 2931 section 3.1).

:func:`build_update` is the requester side: Host Description, Service Description and Service
Discovery Instructions, signed. :func:`update_message` is the reading side, reducing a parsed
packet to the plain :class:`dnssd_srp.model.UpdateMessage` that
:func:`dnssd_srp.registrar.classify_update` judges.

Requester rules built in, each pinned in ``tests/test_srp_message.py``: the KEY of every
Service Description is omitted by default (allowed by section 3.2.5.1 paragraph 6; the SIG(0)
covers the bytes as sent, so an omitted KEY is not signed over); the KEY flags are zero
(paragraph 5); the delete-all precedes the adds for its name (section 3.3.1 paragraph 3); a host
with no addresses is a removal and needs LEASE zero (section 3.2.5.5.1).
"""

from __future__ import annotations

import ipaddress
import secrets
from collections.abc import Sequence
from dataclasses import dataclass

from namespy.enums import DnsOpCode, DnsQR, DnsQType, DnsRClass, DnsRType
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord
from namespy.rdata import RData_PTR, RData_SRV, RData_TXT

from .lease import UpdateLease, from_edns_options, to_edns_option
from .model import OpKind, UpdateMessage, UpdateOp
from .sig0 import SigningKey, key_rr, sign_request

__all__ = [
    "ServiceDefinition",
    "SrpFormatError",
    "build_update",
    "update_message",
]

_CLASS_NONE = 254  # RFC 2136 section 2.4: NONE


class SrpFormatError(ValueError):
    """A DNS message that is not a well-formed RFC 2136 UPDATE (so not an SRP Update either)."""


@dataclass(frozen=True)
class ServiceDefinition:
    """One service instance to register: its names, port and TXT strings."""

    instance: str  # the service instance name, e.g. "My Printer._ipp._tcp.default.service.arpa."
    service: str  # the service name the PTR lives at, e.g. "_ipp._tcp.default.service.arpa."
    port: int
    txt: Sequence[bytes] = (b"",)
    priority: int = 0
    weight: int = 0


def build_update(
    zone: str,
    host: str,
    addresses: Sequence[str],
    services: Sequence[ServiceDefinition],
    lease: UpdateLease,
    signing_key: SigningKey,
    public_key: bytes,
    *,
    now: int,
    ttl: int = 120,
    message_id: int | None = None,
    repeat_service_keys: bool = False,
) -> bytes:
    """Build and sign an SRP Update as RFC 9665 sec. 3 lays it out.

    ``addresses`` are IPv4 or IPv6 literals for the Host Description; none means a removal and
    then ``lease.lease`` must be zero (section 3.2.5.5.1). The Update Lease option is always
    sent (section 3.3.2 paragraph 2) and is refused here when LEASE exceeds KEY-LEASE. ``ttl`` is
    the one TTL given to every added RR, which satisfies section 4 paragraph 3 by construction.
    ``repeat_service_keys`` puts the host KEY in every Service Description; the default omits it
    (section 3.2.5.1 paragraph 6). ``message_id`` defaults to a random ID, as a request needs.

    Raises :class:`ValueError` for a lease that cannot be an SRP lease, a removal with a
    nonzero lease, an unusable address and a service with no TXT string.
    """
    if lease.key_lease is not None and lease.key_lease < lease.lease:
        raise ValueError("LEASE must not exceed KEY-LEASE (RFC 9665 section 3.3.2 paragraph 2)")
    parsed = [ipaddress.ip_address(a) for a in addresses]
    if not parsed and lease.lease != 0:
        raise ValueError("a host with no addresses is a removal and needs LEASE zero (3.2.5.5.1)")
    key = key_rr(public_key, signing_key.algorithm)
    key_wire = key.to_wire()

    def delete_name(name: str) -> DnsRecord:
        # RFC 2136 section 2.5.3: CLASS ANY, TYPE ANY, TTL 0, no RDATA.
        return DnsRecord(name, DnsQType.ANY, DnsRClass.ANY, 0, rdata=b"")

    def add(name: str, rtype: int, rdata: bytes) -> DnsRecord:
        return DnsRecord(name, rtype, DnsRClass.IN, ttl, rdata=rdata)

    updates: list[DnsRecord] = []
    for sv in services:
        if not sv.txt:
            raise ValueError(f"{sv.instance} needs at least one TXT string (section 3.3.1.2)")
        updates.append(add(sv.service, DnsRType.PTR, RData_PTR(sv.instance).to_wire()))
    for sv in services:  # Service Description: delete-all first, then the adds
        updates.append(delete_name(sv.instance))
        srv = RData_SRV(host, sv.priority, sv.weight, sv.port)
        updates.append(add(sv.instance, DnsRType.SRV, srv.to_wire()))
        updates.append(add(sv.instance, DnsRType.TXT, RData_TXT(list(sv.txt)).to_wire()))
        if repeat_service_keys:
            updates.append(add(sv.instance, DnsRType.KEY, key_wire))
    updates.append(delete_name(host))  # Host Description
    updates.append(add(host, DnsRType.KEY, key_wire))
    for address in parsed:
        rtype = DnsRType.A if address.version == 4 else DnsRType.AAAA
        updates.append(add(host, rtype, address.packed))

    packet = DnsPacket(
        secrets.randbits(16) if message_id is None else message_id,
        QR=DnsQR.QUERY,
        OPCODE=DnsOpCode.UPDATE,
        RD=False,
        questions=[DnsQuestion(zone, DnsQType.SOA, DnsRClass.IN)],
        nameservers=updates,
    )
    packet.add_edns(options=[to_edns_option(lease)])
    return sign_request(bytes(packet), signing_key, signer=host, key_tag=key.key_tag, now=now)


def update_message(packet: DnsPacket) -> UpdateMessage:
    """Reduce a parsed UPDATE message to the plain form the SRP rules read (RFC 2136 section 2).

    Raises :class:`SrpFormatError` unless the message is a request with OPCODE UPDATE and exactly
    one Zone entry of TYPE SOA and CLASS IN (RFC 2136 section 2.3: anything else is FORMERR),
    and for an Update RR whose CLASS, TYPE and RDATA are not one of the four forms of section 2.5.
    The SIG(0) and OPT records are in the additional section and are not Update RRs. A malformed
    Update Lease option raises :class:`dnssd_srp.lease.LeaseError`.
    """
    if int(packet.OPCODE) != int(DnsOpCode.UPDATE) or int(packet.QR) != int(DnsQR.QUERY):
        raise SrpFormatError("not an UPDATE request")
    if len(packet.questions) != 1:
        raise SrpFormatError("an UPDATE has exactly one Zone entry (RFC 2136 section 2.3)")
    zone = packet.questions[0]
    if int(zone.qtype) != int(DnsQType.SOA) or int(zone.qclass) != int(DnsRClass.IN):
        raise SrpFormatError("the Zone entry is not SOA IN (RFC 2136 section 2.3)")
    ops: list[UpdateOp] = []
    for record in packet.nameservers:
        rclass, rtype = int(record.rclass), int(record.rtype)
        rdata = bytes(record.rdata)
        if rclass == int(DnsRClass.IN):
            kind = OpKind.ADD
        elif rclass == int(DnsRClass.ANY) and rtype == int(DnsQType.ANY) and not rdata:
            kind = OpKind.DELETE_NAME
        elif rclass == int(DnsRClass.ANY) and not rdata:
            kind = OpKind.DELETE_RRSET
        elif rclass == _CLASS_NONE:
            kind = OpKind.DELETE_RR
        else:
            raise SrpFormatError(f"an Update RR of class {rclass} is not an RFC 2136 form")
        ops.append(UpdateOp(kind, str(record.name), rtype, record.ttl, rdata))
    lease = from_edns_options(packet.edns_options())
    return UpdateMessage(str(zone.name), tuple(ops), len(packet.answers), lease)
