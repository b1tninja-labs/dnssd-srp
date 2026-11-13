"""Plain data for the update path: the records of a DNS Update, with no wire format.

The registrar and requester rows take these rather than bytes, so the rules of RFC 9665 can
be written and tested before (and independently of) any DNS message codec. The wire reader
that fills them is the shared codec's job (:mod:`namespy`), not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .lease import UpdateLease

__all__ = ["OpKind", "UpdateMessage", "UpdateOp", "UpdateRR", "fold_name", "rrset_key"]

_U32_MAX = 0xFFFFFFFF
_ASCII_FOLD = {ord(c): ord(c) + 32 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}


def _fold(name: str) -> str:
    """ASCII-only case folding and no root terminator: DNS names compare octet-wise."""
    return name.translate(_ASCII_FOLD).rstrip(".")


@dataclass(frozen=True)
class UpdateRR:
    """One resource record in the Update section: owner, TYPE, TTL and RDATA octets."""

    name: str
    rrtype: int
    ttl: int
    rdata: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.ttl <= _U32_MAX:
            raise ValueError(f"TTL {self.ttl} is outside the 32-bit field 0..2**32-1")
        if not 0 <= self.rrtype <= 0xFFFF:
            raise ValueError(f"TYPE {self.rrtype} is outside 0..65535")


def rrset_key(record: UpdateRR) -> tuple[str, int]:
    """The RRset an RR belongs to: owner name (ASCII-folded, root terminator ignored) and TYPE."""
    return (_fold(record.name), record.rrtype)


def fold_name(name: str) -> str:
    """The comparison form of a name: ASCII-folded, no root terminator (RFC 4343 section 2.1)."""
    return _fold(name)


class OpKind(Enum):
    """The four update forms of RFC 2136 section 2.5, told apart by CLASS, TYPE and RDATA."""

    ADD = "add"  # 2.5.1: CLASS is the zone class
    DELETE_RRSET = "delete-rrset"  # 2.5.2: CLASS ANY, a specific TYPE, no RDATA
    DELETE_NAME = "delete-name"  # 2.5.3: CLASS ANY, TYPE ANY, no RDATA
    DELETE_RR = "delete-rr"  # 2.5.4: CLASS NONE, the RDATA of the RR to remove


@dataclass(frozen=True)
class UpdateOp:
    """One RR of the Update section. ``rdata`` is standalone (uncompressed) octets."""

    kind: OpKind
    name: str
    rrtype: int
    ttl: int = 0
    rdata: bytes = b""


@dataclass(frozen=True)
class UpdateMessage:
    """A DNS Update reduced to what the SRP rules read (RFC 2136 section 2).

    ``prerequisites`` is the count of the Prerequisite section (PRCOUNT): SRP allows none.
    ``lease`` is the Update Lease option, or None when the message carries none.
    """

    zone: str
    ops: tuple[UpdateOp, ...]
    prerequisites: int = 0
    lease: UpdateLease | None = None
