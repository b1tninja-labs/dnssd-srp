"""update validation and lease maintenance (RFC 9665 sec. 3.3, sec. 4, sec. 5).

:func:`check_ttl_consistency` and :func:`ttl_for` are implemented (RFC 9665 sec. 4). The rest
of this module is a placeholder until the milestone named in ROADMAP.md lands: a stub raises
instead of returning a plausible empty value, because a protocol library that silently answers
nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .model import UpdateRR, rrset_key

if TYPE_CHECKING:
    from typing import Any

    ValidationOutcome = Any  # placeholder: give it a real type in the milestone that needs it
    ZoneContext = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "RCODE_REFUSED",
    "TtlPolicy",
    "check_ttl_consistency",
    "ttl_for",
    "validate_update",
]

#: The REFUSED response code, 5 (RFC 8490 sec. 5.4.1 paragraph 10 lists it with its value).
#: RFC 9665 sec. 4 paragraph 3 says an update with inconsistent TTLs "MUST be rejected with a
#: Refused RCODE".
RCODE_REFUSED = 5

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


def validate_update(update: bytes, zone: ZoneContext) -> ValidationOutcome:
    """Pending behaviour defined by RFC 9665 sec. 3.3.

    Not implemented yet. See the ``registrar.validate_update()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("validate_update() is not implemented: RFC 9665 sec. 3.3")


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
