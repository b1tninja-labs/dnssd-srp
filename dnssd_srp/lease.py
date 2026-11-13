"""The EDNS(0) Update Lease option (RFC 9664 section 4).

RFC 9665 makes this option mandatory in every SRP Update and in its response (section 3.3.2
paragraph 2), so neither a requester nor a registrar can pass without it. The option is an
OPT RR option, code UPDATE-LEASE (2), with OPTION-LENGTH 4 (LEASE) or 8 (LEASE and KEY-LEASE),
both unsigned 32-bit seconds in network order.

This module encodes and decodes the *option*. Building the OPT RR around it is the DNS
codec's job: :func:`to_edns_option` and :func:`from_edns_options` hand it to and take it from
:mod:`namespy.edns`, the one DNS codec (a sibling dependency, not a second copy).

Which variant to answer with is RFC 9664 section 4.3: a server answers an 8-byte request with
8 bytes, and treats a 4-byte request as both lease and key lease and answers with 4 bytes; a
requester that sent 8 bytes and got 4 treats it as both. :meth:`UpdateLease.effective_key_lease`
and :func:`response_variant` carry that. Nothing here invents a default lease: RFC 9665
section 5.1 offers 2 hours and 14 days only as values "thought to be good choices", so they
are named, configurable constants and the caller chooses.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from namespy.edns import EdnsOption, find_option

__all__ = [
    "UPDATE_LEASE_OPTION_CODE",
    "LeaseError",
    "UpdateLease",
    "decode_update_lease",
    "encode_update_lease",
    "from_edns_options",
    "response_variant",
    "to_edns_option",
]

#: RFC 9664 section 4, Table 1: OPTION-CODE UPDATE-LEASE.
UPDATE_LEASE_OPTION_CODE = 2

_U32_MAX = 0xFFFFFFFF
_OPTION_HEAD = struct.Struct("!HH")


class LeaseError(ValueError):
    """An Update Lease option that is not well formed."""


@dataclass(frozen=True)
class UpdateLease:
    """LEASE and optional KEY-LEASE, in seconds. ``key_lease`` None is the 4-byte variant."""

    lease: int
    key_lease: int | None = None

    def __post_init__(self) -> None:
        for name, value in (("LEASE", self.lease), ("KEY-LEASE", self.key_lease)):
            if value is not None and not 0 <= value <= _U32_MAX:
                raise LeaseError(f"{name} {value} is outside 0..2**32-1")

    @property
    def effective_key_lease(self) -> int:
        """The key lease in force: KEY-LEASE, or LEASE for the 4-byte variant (section 4.3)."""
        return self.lease if self.key_lease is None else self.key_lease

    def is_srp_valid(self) -> bool:
        """RFC 9665 section 3.3.2 paragraph 2: LEASE must be at most KEY-LEASE.

        A policy of the registrar, not a codec error: a decoded option with LEASE above KEY-LEASE
        is well formed, and what it makes is a DNS Update that "is not an SRP Update".
        """
        return self.lease <= self.effective_key_lease


def encode_update_lease(value: UpdateLease) -> bytes:
    """The option octets: OPTION-CODE, OPTION-LENGTH, LEASE and optional KEY-LEASE (RFC 9664 4)."""
    if value.key_lease is None:
        return _OPTION_HEAD.pack(UPDATE_LEASE_OPTION_CODE, 4) + struct.pack("!I", value.lease)
    return _OPTION_HEAD.pack(UPDATE_LEASE_OPTION_CODE, 8) + struct.pack(
        "!II", value.lease, value.key_lease
    )


def decode_update_lease(data: bytes) -> UpdateLease:
    """Read one option (code and length included); refuse anything but a 4- or 8-byte body.

    Raises :class:`LeaseError` for a short header, a code other than 2, a declared length beyond
    the buffer or trailing octets after the option, and a length other than 4 or 8
    (RFC 9664 section 4, Table 1).
    """
    if len(data) < _OPTION_HEAD.size:
        raise LeaseError(f"option of {len(data)} octets is shorter than its 4-octet header")
    code, length = _OPTION_HEAD.unpack_from(data)
    if code != UPDATE_LEASE_OPTION_CODE:
        raise LeaseError(f"OPTION-CODE {code} is not UPDATE-LEASE ({UPDATE_LEASE_OPTION_CODE})")
    body = data[_OPTION_HEAD.size :]
    if length > len(body):
        raise LeaseError(f"OPTION-LENGTH {length} runs past the {len(body)} octets present")
    if length < len(body):
        raise LeaseError(f"{len(body) - length} octet(s) follow the option")
    if length == 4:
        return UpdateLease(struct.unpack("!I", body)[0])
    if length == 8:
        lease, key_lease = struct.unpack("!II", body)
        return UpdateLease(lease, key_lease)
    raise LeaseError(f"OPTION-LENGTH {length} is neither 4 nor 8 (RFC 9664 section 4)")


def response_variant(
    request: UpdateLease, granted_lease: int, granted_key_lease: int
) -> UpdateLease:
    """The response option for a request, in the variant RFC 9664 section 4.3 requires.

    An 8-byte request is answered with an 8-byte option. A 4-byte request "specifying both the
    lease duration and the KEY lease duration" is answered with a 4-byte option, so the two
    granted values must then be equal: otherwise the server could not tell the requester what
    it granted, and this raises :class:`LeaseError` instead of dropping the key lease.
    """
    if request.key_lease is not None:
        return UpdateLease(granted_lease, granted_key_lease)
    if granted_lease != granted_key_lease:
        raise LeaseError(
            "a 4-byte request must be answered with a 4-byte option, so the granted LEASE and "
            "KEY-LEASE must be equal (RFC 9664 section 4.3)"
        )
    return UpdateLease(granted_lease)


def to_edns_option(value: UpdateLease) -> EdnsOption:
    """The same option as a :class:`namespy.edns.EdnsOption`, ready for an OPT RR."""
    return EdnsOption(UPDATE_LEASE_OPTION_CODE, encode_update_lease(value)[_OPTION_HEAD.size :])


def from_edns_options(options: Iterable[EdnsOption]) -> UpdateLease | None:
    """The Update Lease among an OPT RR's options, or ``None`` when absent.

    Absent is information (RFC 9664 section 4.2 paragraph 2: the server does not support it),
    so it is not turned into a default. A present but malformed option raises
    :class:`LeaseError`.
    """
    option = find_option(tuple(options), UPDATE_LEASE_OPTION_CODE)
    if option is None:
        return None
    return decode_update_lease(_OPTION_HEAD.pack(option.code, len(option.data)) + option.data)
