"""update validation and lease maintenance (RFC 9665 sec. 3.3, sec. 4, sec. 5).

:func:`check_ttl_consistency` and :func:`ttl_for` are implemented (RFC 9665 sec. 4). The rest
of this module is a placeholder until the milestone named in ROADMAP.md lands: a stub raises
instead of returning a plausible empty value, because a protocol library that silently answers
nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from namespy.enums import DnsResponseCode, DnsRType
from namespy.packet import DnsPacket
from namespy.rdata import RData_KEY, RData_PTR, RData_SRV
from namespy.wire import DnsPacketParseError

from .lease import LeaseError, UpdateLease
from .model import OpKind, UpdateMessage, UpdateOp, UpdateRR, fold_name, rrset_key
from .srp import SrpFormatError, update_message

__all__ = [
    "RCODE_NOERROR",
    "RCODE_REFUSED",
    "RCODE_YXDOMAIN",
    "DiscoveryInstruction",
    "NotSrp",
    "ServiceInstruction",
    "SrpUpdate",
    "TtlPolicy",
    "ValidationOutcome",
    "ZoneContext",
    "check_fcfs",
    "check_signature",
    "check_ttl_consistency",
    "classify_update",
    "ttl_for",
    "validate_update",
]

#: The REFUSED response code, 5 (RFC 8490 sec. 5.4.1 paragraph 10 lists it with its value).
#: RFC 9665 sec. 4 paragraph 3 says an update with inconsistent TTLs "MUST be rejected with a
#: Refused RCODE".
RCODE_REFUSED = 5
RCODE_NOERROR = 0
#: RFC 2136 section 2.2 (YXDomain, 6), which RFC 9665 section 3.3.3 paragraph 1 returns for a name
#: already owned by a different SIG(0) key.
RCODE_YXDOMAIN = 6

_U32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class TtlPolicy:
    """Operator-configurable TTL bounds, in seconds (RFC 9665 sec. 4 paragraph 5).

    "TTL minimums and maximums SHOULD be configurable by the operator of the SRP registrar", and
    the RFC gives no numbers, so there are no defaults here either.
    """

    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if not 0 <= self.minimum <= self.maximum <= _U32_MAX:
            raise ValueError(
                f"TTL policy needs 0 <= minimum <= maximum <= 2**32-1, got "
                f"{self.minimum}..{self.maximum}"
            )


def check_ttl_consistency(records: Sequence[UpdateRR]) -> bool:
    """True when every RRset in the update has one TTL (RFC 9665 sec. 4 paragraph 3).

    "SRP registrars MUST check that the TTLs for all RRs within each RRset contained within an SRP
    Update are the same. If they are not, the SRP update MUST be rejected with a Refused RCODE":
    a False result means REFUSED (:data:`RCODE_REFUSED`). An RRset is the owner name and TYPE,
    compared with ASCII case folding. Different RRsets may carry different TTLs, and an empty
    update is vacuously consistent.
    """
    seen: dict[tuple[str, int], int] = {}
    for record in records:
        key = rrset_key(record)
        if seen.setdefault(key, record.ttl) != record.ttl:
            return False
    return True


def ttl_for(requested_ttl: int, lease: int, policy: TtlPolicy) -> int:
    """The TTL a registrar publishes for a requested one (RFC 9665 sec. 4 paragraph 5).

    Requested TTLs "are advisory", and registrars "may override" them. The result is the requested
    value clamped into the operator's ``[minimum, maximum]``, then never above ``lease``, because
    "the TTL SHOULD NOT ever be longer than the lease time": where the two SHOULDs collide (a
    lease shorter than the policy minimum), the lease wins, since a cached record that outlives
    its lease is the staleness the lease exists to prevent. ``lease`` is the *granted* lease: a
    response TTL above the lease *remaining* later is "not an error" (RFC 9665 sec. 5.1 paragraph
    9), so this is a ceiling on what is published, not a check on what is served. Every RR of an RRset must be given the
    same result (paragraph 4), which is the caller's to arrange: call this once per RRset.
    """
    for name, value in (("requested TTL", requested_ttl), ("lease", lease)):
        if not 0 <= value <= _U32_MAX:
            raise ValueError(f"{name} {value} is outside 0..2**32-1")
    clamped = min(max(requested_ttl, policy.minimum), policy.maximum)
    return min(clamped, lease)


# ------------------------------------------------------------------ classification


@dataclass(frozen=True)
class NotSrp:
    """The message is not an SRP Update (RFC 9665 section 3.3.2); ``reason`` says which rule."""

    reason: str


@dataclass(frozen=True)
class ServiceInstruction:
    """A Service Description Instruction (section 3.3.1.2). ``srv`` None means a deletion."""

    name: str
    srv: RData_SRV | None
    txt_count: int
    key: RData_KEY | None


@dataclass(frozen=True)
class DiscoveryInstruction:
    """A Service Discovery Instruction (section 3.3.1.1): one PTR add or delete."""

    service: str
    instance: str
    add: bool


@dataclass(frozen=True)
class SrpUpdate:
    """A message accepted as an SRP Update, split into its three kinds of instruction."""

    zone: str
    host: str
    key: RData_KEY
    addresses: tuple[UpdateOp, ...]
    services: tuple[ServiceInstruction, ...]
    discovery: tuple[DiscoveryInstruction, ...]
    lease: UpdateLease

    @property
    def removes_host(self) -> bool:
        """The shape of section 3.2.5.5.1: LEASE zero and nothing added for the host but the KEY."""
        return self.lease.lease == 0 and not self.addresses


_ADDRESS_TYPES = (int(DnsRType.A), int(DnsRType.AAAA))
_PTR = int(DnsRType.PTR)
_SRV = int(DnsRType.SRV)
_TXT = int(DnsRType.TXT)
_KEY = int(DnsRType.KEY)


def _in_zone(name: str, zone: str) -> bool:
    return zone == "" or name == zone or name.endswith("." + zone)


def classify_update(message: UpdateMessage) -> SrpUpdate | NotSrp:
    """Decide whether a DNS Update is an SRP Update, and split it (RFC 9665 section 3.3).

    Section 3.3.2 paragraph 1: exactly one Host Description Instruction, every other change a
    Service Discovery or Service Description Instruction, no prerequisites; paragraph 2: an
    Update Lease option with LEASE at most KEY-LEASE. Anything else is :class:`NotSrp`, which
    paragraph 3 says is processed as a plain DNS Update or REFUSED.

    The shapes are those of sections 3.3.1.1 to 3.3.1.3: a host is one "Delete All RRsets From A
    Name", one KEY add and zero or more A or AAAA adds; a service instance is one delete-all, at
    most one KEY add, at most one SRV add targeting the host and, exactly when there is an SRV,
    at least one TXT add; a PTR add needs an SRV-bearing instance and a PTR delete one without.
    A delete-all must precede the adds for its name (section 3.3.1 paragraph 3). A service KEY
    must equal the host KEY (section 3.3.1.2). Names compare ASCII-folded.

    A host removal (section 3.2.5.5.1) still carries its KEY add: section 3.3.1.3 paragraph 3
    requires exactly one, while section 3.2.5.5.1 paragraph 1 says "no Add to an RRSet
    instructions for that hostname". The two cannot both hold; the Host Description Instruction
    definition is followed, because the KEY is what the SIG(0) is checked against.

    What this does not do is the stored-state and signature work: :func:`check_fcfs`,
    :mod:`dnssd_srp.sig0`, :func:`check_ttl_consistency`.
    """
    if message.prerequisites:
        return NotSrp("the update has prerequisites (section 3.3.2 paragraph 1)")
    lease = message.lease
    if lease is None:
        return NotSrp("no Update Lease option (section 3.3.2 paragraph 2)")
    if lease.key_lease is not None and lease.key_lease < lease.lease:
        return NotSrp("KEY-LEASE is shorter than LEASE (section 3.3.2 paragraph 2)")
    zone = fold_name(message.zone)
    ptrs: list[UpdateOp] = []
    groups: dict[str, list[tuple[int, UpdateOp]]] = {}
    for index, op in enumerate(message.ops):
        name = fold_name(op.name)
        if not _in_zone(name, zone):
            return NotSrp(f"{op.name} is outside the zone (section 3.3.1 paragraph 4)")
        if op.rrtype == _PTR and op.kind is not OpKind.DELETE_NAME:
            if op.kind not in (OpKind.ADD, OpKind.DELETE_RR):
                return NotSrp("a PTR change other than add or delete-RR (section 3.3.1.1)")
            ptrs.append(op)
        else:
            groups.setdefault(name, []).append((index, op))
    if not groups:
        return NotSrp("no Host Description Instruction (section 3.3.2 paragraph 1)")
    discovery: list[DiscoveryInstruction] = []
    instance_names: set[str] = set()
    for op in ptrs:
        try:
            target = RData_PTR.parse_from(op.rdata, 0, len(op.rdata))
        except ValueError:
            return NotSrp("a PTR with unreadable RDATA")
        instance = fold_name(str(target))
        instance_names.add(instance)
        discovery.append(DiscoveryInstruction(fold_name(op.name), instance, op.kind is OpKind.ADD))
    for name, entries in groups.items():
        if any(op.rrtype in (_SRV, _TXT) and op.kind is OpKind.ADD for _, op in entries):
            instance_names.add(name)
    if any(d.service in groups for d in discovery):
        return NotSrp("a Service Discovery owner also carries other changes (section 3.3.1.1)")
    hosts = [name for name in groups if name not in instance_names]
    if len(hosts) != 1:
        return NotSrp(f"{len(hosts)} Host Description Instructions (section 3.3.2 paragraph 1)")
    host = hosts[0]
    for name in sorted(instance_names):
        if name not in groups:
            return NotSrp(f"PTR target {name} has no Service Description Instruction (3.3.1.1)")

    host_key, addresses, problem = _host_description(groups[host])
    if problem is not None or host_key is None:
        return NotSrp(problem or "the host description is unreadable")
    services: list[ServiceInstruction] = []
    for name in sorted(instance_names):
        service = _service_description(name, groups[name], host, host_key)
        if isinstance(service, str):
            return NotSrp(service)
        services.append(service)
    by_name = {service.name: service for service in services}
    for entry in discovery:
        has_srv = by_name[entry.instance].srv is not None
        if entry.add and not has_srv:
            return NotSrp(f"PTR add to {entry.instance}, which has no SRV add (section 3.3.1.1)")
        if not entry.add and has_srv:
            return NotSrp(f"PTR delete for {entry.instance}, which is being added (3.3.1.1)")
    return SrpUpdate(zone, host, host_key, addresses, tuple(services), tuple(discovery), lease)


def _decode_key(op: UpdateOp) -> RData_KEY | None:
    try:
        return RData_KEY.parse_from(op.rdata, 0, len(op.rdata))
    except ValueError:
        return None


def _host_description(
    entries: Sequence[tuple[int, UpdateOp]],
) -> tuple[RData_KEY | None, tuple[UpdateOp, ...], str | None]:
    deletes = [i for i, op in entries if op.kind is OpKind.DELETE_NAME]
    keys = [(i, op) for i, op in entries if op.kind is OpKind.ADD and op.rrtype == _KEY]
    addresses = [
        (i, op) for i, op in entries if op.kind is OpKind.ADD and op.rrtype in _ADDRESS_TYPES
    ]
    if len(deletes) != 1:
        return None, (), "the host needs exactly one delete-all-RRsets (section 3.3.1.3)"
    if len(keys) != 1:
        return None, (), "the host needs exactly one KEY add (section 3.3.1.3)"
    if len(deletes) + len(keys) + len(addresses) != len(entries):
        return None, (), "the host changes something besides KEY, A and AAAA (section 3.3.1.3)"
    if any(i < deletes[0] for i, _ in keys + addresses):
        return None, (), "an add precedes the delete-all for the host (section 3.3.1 paragraph 3)"
    key = _decode_key(keys[0][1])
    if key is None:
        return None, (), "the host KEY is unreadable"
    return key, tuple(op for _, op in addresses), None


def _service_description(
    name: str, entries: Sequence[tuple[int, UpdateOp]], host: str, host_key: RData_KEY
) -> ServiceInstruction | str:
    deletes = [i for i, op in entries if op.kind is OpKind.DELETE_NAME]
    adds = [(i, op) for i, op in entries if op.kind is OpKind.ADD]
    if len(deletes) != 1:
        return f"{name} needs exactly one delete-all-RRsets (section 3.3.1.2)"
    if len(deletes) + len(adds) != len(entries):
        return f"{name} has a change that is not an add or the delete-all (section 3.3.1.2)"
    keys = [op for _, op in adds if op.rrtype == _KEY]
    srvs = [op for _, op in adds if op.rrtype == _SRV]
    txts = [op for _, op in adds if op.rrtype == _TXT]
    if len(keys) + len(srvs) + len(txts) != len(adds):
        return f"{name} adds a type other than KEY, SRV or TXT (section 3.3.1.2 paragraph 3)"
    if len(keys) > 1 or len(srvs) > 1:
        return f"{name} has more than one KEY or SRV add (section 3.3.1.2)"
    if bool(srvs) != bool(txts):
        return f"{name}: SRV and TXT adds come together or not at all (section 3.3.1.2)"
    if any(i < deletes[0] for i, _ in adds):
        return f"an add precedes the delete-all for {name} (section 3.3.1 paragraph 3)"
    key = None
    if keys:
        key = _decode_key(keys[0])
        if key is None or key != host_key:
            return f"the KEY of {name} differs from the host KEY (section 3.3.1.2)"
    srv = None
    if srvs:
        try:
            srv = RData_SRV.parse_from(srvs[0].rdata, 0, len(srvs[0].rdata))
        except ValueError:
            return f"the SRV of {name} is unreadable"
        if fold_name(str(srv.target)) != host:
            return f"the SRV target of {name} is not the host name (section 3.3.1.2)"
    return ServiceInstruction(name, srv, len(txts), key)


# ------------------------------------------------------------------ FCFS and signature


def check_fcfs(update: SrpUpdate, existing_keys: Mapping[str, bytes]) -> int:
    """YXDOMAIN when an existing KEY disagrees with the update's, else NOERROR (RFC 9665 3.3.3).

    ``existing_keys`` maps a folded owner name to the KEY RDATA octets stored for it. The host is
    checked against the host KEY, each service instance against its own KEY or, where it was
    omitted, the host's (section 3.3.3 paragraph 1). A name with no stored KEY is free.
    """
    wanted = {update.host: update.key.to_wire()}
    for service in update.services:
        wanted[service.name] = (service.key or update.key).to_wire()
    for name, key in wanted.items():
        stored = existing_keys.get(fold_name(name))
        if stored is not None and bytes(stored) != key:
            return RCODE_YXDOMAIN
    return RCODE_NOERROR


def check_signature(message: bytes, update: SrpUpdate, *, now: int) -> int:
    """REFUSED unless the SIG(0) verifies under the host KEY (RFC 9665 section 3.3.3 paragraph 2).

    Only algorithm 13 is implemented; a KEY of another algorithm cannot be verified and is
    refused, never accepted unchecked.
    """
    from .sig0 import Sig0Error, VerifyKey, verify_request

    try:
        ok = verify_request(
            message, VerifyKey(update.key.algorithm, update.key.public_key), now=now
        )
    except Sig0Error:
        return RCODE_REFUSED
    return RCODE_NOERROR if ok else RCODE_REFUSED


@dataclass(frozen=True)
class ZoneContext:
    """What the registrar knows about the zone: its origin and the KEY stored for each name."""

    origin: str
    keys: Mapping[str, bytes]


@dataclass(frozen=True)
class ValidationOutcome:
    """The response code for an update, the classified update when it got that far, and why."""

    rcode: int
    update: SrpUpdate | None
    reason: str


def validate_update(update: bytes, zone: ZoneContext, *, now: int) -> ValidationOutcome:
    """Run an update through RFC 9665 sec. 3.3 in order and say what the registrar answers.

    Parse (FORMERR when the bytes are not a DNS message or not an RFC 2136 UPDATE of this zone),
    classify (section 3.3.2: not an SRP Update is REFUSED, the registrar here does not process
    plain updates, which paragraph 3 allows), TTL consistency (section 4 paragraph 3: REFUSED),
    FCFS names (section 3.3.3 paragraph 1: YXDOMAIN) and the SIG(0) (paragraph 2: REFUSED). Only
    an update that passes all five is NOERROR and carries the classified :class:`SrpUpdate`.
    Applying it to a zone, the leases and the response message are not done here.
    """
    try:
        packet, _ = DnsPacket.parse(update)
        message = update_message(packet)
        lease_error = None
    except (DnsPacketParseError, SrpFormatError) as exc:
        return ValidationOutcome(int(DnsResponseCode.FORMAT_ERROR), None, str(exc))
    except LeaseError as exc:
        message, lease_error = None, str(exc)
    if lease_error is not None or message is None:
        return ValidationOutcome(RCODE_REFUSED, None, f"malformed Update Lease: {lease_error}")
    if fold_name(message.zone) != fold_name(zone.origin):
        return ValidationOutcome(int(DnsResponseCode.NOT_ZONE), None, "not this zone (RFC 2136)")
    classified = classify_update(message)
    if isinstance(classified, NotSrp):
        return ValidationOutcome(RCODE_REFUSED, None, classified.reason)
    records = [
        UpdateRR(op.name, op.rrtype, op.ttl, op.rdata)
        for op in message.ops
        if op.kind is OpKind.ADD
    ]
    if not check_ttl_consistency(records):
        return ValidationOutcome(
            RCODE_REFUSED, classified, "TTLs differ within an RRset (section 4)"
        )
    if check_fcfs(classified, zone.keys) == RCODE_YXDOMAIN:
        return ValidationOutcome(RCODE_YXDOMAIN, classified, "a name is owned by a different key")
    if check_signature(update, classified, now=now) != RCODE_NOERROR:
        return ValidationOutcome(RCODE_REFUSED, classified, "the SIG(0) does not verify")
    return ValidationOutcome(RCODE_NOERROR, classified, "valid SRP Update")
