"""SIG(0) sign and verify, ECDSA P-256 (RFC 2931, RFC 9665 sec. 6.6).

One algorithm is implemented, the one RFC 9665 section 6.6 makes mandatory: ECDSAP256SHA256,
DNSSEC algorithm 13. Its key is the 64 octets ``x | y`` and its signature the 64 octets
``r | s`` (RFC 6605 section 4); a DER signature is not a DNS signature and is refused.

The arithmetic is the one thing taken from a third party, under the portfolio rule that
`cryptography` supplies signature primitives and nothing else (``PORTFOLIO.md`` section 9 item
15): verification goes through :func:`namespy.crypto.verify_dnskey_signature` (namespy's own
backend boundary, which already pins the 13/``x|y``/``r|s`` layout), and signing imports
`cryptography` here, inside :func:`sign`, so ``import dnssd_srp`` stays dependency-light. Both
need the ``crypto`` extra. The SIG record layout, the signed-data construction and the
time-window check are ours.

What is *not* here yet: building the SIG RDATA and the SIG(0) RR from a DNS message (the
layout is RFC 2535 section 4.1, which RFC 2931 section 3 paragraph 1 keeps normative for
SIG(0) although RFC 2535 itself is obsolete), and the SHOULD set of RFC 9665 section 6.6, which
points at RFC 8624 (obsolete; RFC 9904 moved its table to the IANA registries) and so is read
from the registry rather than a table here. See the ``sig0.`` rows of ROADMAP.md.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass

from namespy.crypto import MissingCryptoError, SignatureMaterialError, verify_dnskey_signature

__all__ = [
    "ALGORITHM_ECDSAP256SHA256",
    "MAX_SKEW_SECONDS",
    "Sig0Error",
    "SigningKey",
    "VerifyKey",
    "sign",
    "signed_data",
    "verify",
    "within_validity",
]

#: RFC 6605 section 4 paragraph 4: DNSKEY and RRSIG RRs for ECDSA P-256 with SHA-256 are number 13.
ALGORITHM_ECDSAP256SHA256 = 13

#: RFC 2931 section 3.3 paragraph 1: the bracket "should not normally extend further than 5
#: minutes into the past and 5 minutes into the future".
MAX_SKEW_SECONDS = 300

_COORDINATE = 32
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class Sig0Error(ValueError):
    """A key, signature or algorithm this module will not act on."""


@dataclass(frozen=True)
class VerifyKey:
    """A public key: DNSSEC algorithm number and the ``x | y`` octets (RFC 6605 section 4)."""

    algorithm: int
    public_key: bytes


@dataclass(frozen=True)
class SigningKey:
    """A private key: DNSSEC algorithm number and the 32-octet big-endian scalar."""

    algorithm: int
    private_scalar: bytes

    def __post_init__(self) -> None:
        if self.algorithm != ALGORITHM_ECDSAP256SHA256:
            raise Sig0Error(f"algorithm {self.algorithm} is not implemented (only 13)")
        if len(self.private_scalar) != _COORDINATE:
            raise Sig0Error(
                f"a P-256 scalar is {_COORDINATE} octets, got {len(self.private_scalar)}"
            )
        if not 0 < int.from_bytes(self.private_scalar, "big") < _ORDER:
            raise Sig0Error("the private scalar is zero or not below the group order")


def signed_data(rdata_without_signature: bytes, request: bytes) -> bytes:
    """The octets a request SIG(0) signs: ``data = RDATA | request - SIG(0)`` (RFC 2931 3.1).

    ``rdata_without_signature`` is the SIG RDATA "entirely omitting (not just zeroing) the
    signature subfield" and ``request`` is the DNS message "including DNS header ... before the
    request RR counts have been adjusted for the inclusion of the SIG(0)", which the caller must
    pass as it was before the SIG(0) was appended.
    """
    return bytes(rdata_without_signature) + bytes(request)


def within_validity(
    inception: int, expiration: int, now: int, skew: int = MAX_SKEW_SECONDS
) -> bool:
    """Whether ``now`` lies in the SIG(0) lifetime bracket (RFC 2931 section 3.3).

    ``inception`` and ``expiration`` are the SIG fields as 32-bit seconds; ``now`` is passed in
    so nothing reads a clock. The bracket is rejected when it extends more than ``skew``
    seconds on either side of ``now`` (default 5 minutes, the RFC's "should not normally"), which
    is the replay window, and when ``now`` is outside it. Serial-number wraparound (RFC 4034
    section 3.1.5) is not handled; callers pass seconds since the epoch.
    """
    if inception > expiration:
        return False
    if not inception <= now <= expiration:
        return False
    return now - inception <= skew and expiration - now <= skew


def sign(message: bytes, key: SigningKey) -> bytes:
    """Sign ``message`` with ECDSA P-256 and return the 64-octet ``r | s`` (RFC 2931, RFC 9665 sec. 6.6).

    ``message`` is the data of RFC 2931 section 3.1 (:func:`signed_data`). Needs the ``crypto``
    extra; raises :class:`namespy.crypto.MissingCryptoError` when it is absent.
    """
    try:
        ec = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ec")
        hashes = importlib.import_module("cryptography.hazmat.primitives.hashes")
        utils = importlib.import_module("cryptography.hazmat.primitives.asymmetric.utils")
    except ImportError as exc:
        raise MissingCryptoError(
            "cannot sign a SIG(0): install dnssd-srp[crypto] (the `cryptography` distribution)"
        ) from exc
    private = ec.derive_private_key(int.from_bytes(key.private_scalar, "big"), ec.SECP256R1())
    der = private.sign(bytes(message), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(_COORDINATE, "big") + s.to_bytes(_COORDINATE, "big")


def verify(message: bytes, signature: bytes, key: VerifyKey) -> bool:
    """Verify a SIG(0) signature over ``message`` (RFC 2931).

    True only when ECDSA P-256 verification succeeds. Any algorithm other than 13 raises
    :class:`Sig0Error` and never returns True (RFC 9665 sec. 6.6: requesters "MUST NOT assume that
    any algorithm numbered lower than 13 is available"). A signature that is not exactly 64 octets,
    or whose ``r`` or ``s`` is zero or not below the group order, is rejected with False. A public
    key that is not 64 octets on the curve raises :class:`Sig0Error`: that is a bad key, not a
    forged message. Needs the ``crypto`` extra for the arithmetic.
    """
    if key.algorithm != ALGORITHM_ECDSAP256SHA256:
        raise Sig0Error(f"algorithm {key.algorithm} is not implemented (only 13)")
    signature = bytes(signature)
    if len(signature) != 2 * _COORDINATE:
        return False
    r = int.from_bytes(signature[:_COORDINATE], "big")
    s = int.from_bytes(signature[_COORDINATE:], "big")
    if not (0 < r < _ORDER and 0 < s < _ORDER):
        return False
    try:
        return bool(
            verify_dnskey_signature(key.algorithm, key.public_key, signature, bytes(message))
        )
    except SignatureMaterialError as exc:
        raise Sig0Error(f"unusable key: {exc}") from exc
