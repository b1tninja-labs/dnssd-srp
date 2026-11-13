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

The SIG(0) record itself is namespy's :class:`namespy.rdata.RData_SIG` (RFC 2535 section 4.1,
which RFC 2931 section 3 paragraph 1 keeps normative for SIG(0) although RFC 2535 is obsolete) and
the public key travels as :class:`namespy.rdata.RData_KEY`; :func:`sign_request` appends the
record to a request and :func:`verify_request` checks one.

What is *not* here yet: the SHOULD set of RFC 9665 section 6.6, which points at RFC 8624
(obsolete; RFC 9904 moved its table to the IANA registries) and so is read from the registry
rather than a table here. See the ``sig0.`` rows of ROADMAP.md.
"""

from __future__ import annotations

import importlib
import struct
from dataclasses import dataclass

from namespy.crypto import MissingCryptoError, SignatureMaterialError, verify_dnskey_signature
from namespy.enums import DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord
from namespy.rdata import RData_KEY, RData_SIG
from namespy.wire import DnsPacketParseError

__all__ = [
    "ALGORITHM_ECDSAP256SHA256",
    "KEY_PROTOCOL_DNSSEC",
    "MAX_SKEW_SECONDS",
    "Sig0Error",
    "Sig0Parts",
    "SigningKey",
    "VerifyKey",
    "key_rr",
    "sign",
    "sign_request",
    "signed_data",
    "split_sig0",
    "verify",
    "verify_request",
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


#: The KEY protocol octet an SRP requester uses: 3, "dnssec" (RFC 2535 section 3.1.3). RFC 9665
#: does not state the value; it says the KEY is "defined in" RFC 4034 and the flags are zero.
KEY_PROTOCOL_DNSSEC = 3


def key_rr(public_key: bytes, algorithm: int = ALGORITHM_ECDSAP256SHA256) -> RData_KEY:
    """The KEY RDATA of an SRP update: flags zero (RFC 9665 section 3.2.5.1 paragraph 5), protocol 3."""
    return RData_KEY(0, KEY_PROTOCOL_DNSSEC, algorithm, bytes(public_key))


def _sig_rr(rdata: RData_SIG) -> DnsRecord:
    """Owner root, class ANY, TTL 0: what RFC 2931 section 3 paragraph 3 says a SIG(0) SHOULD be."""
    return DnsRecord(DomainName("."), DnsRType.SIG, DnsRClass.ANY, 0, rdata=rdata)


def _with_extra_additional(message: bytes, record: bytes) -> bytes:
    arcount = struct.unpack_from("!H", message, 10)[0]
    if arcount == 0xFFFF:
        raise Sig0Error("the additional section is full")
    return message[:10] + struct.pack("!H", arcount + 1) + message[12:] + record


def sign_request(
    request: bytes,
    key: SigningKey,
    *,
    signer: str,
    key_tag: int,
    now: int,
    before: int = 60,
    after: int = 240,
) -> bytes:
    """Append a SIG(0) to ``request`` and return the signed message (RFC 2931 section 3.1).

    The signature covers ``RDATA | request`` where ``request`` is the message as it stands, with
    ARCOUNT *not* yet counting the SIG(0) (section 3.1 paragraph 2), and RDATA is the SIG RDATA
    with the signature omitted. The SIG(0) goes last in the additional section, so the OPT record
    the caller already added stays ahead of it. ``signer`` is the host name that owns the KEY
    (section 3 paragraph 2). The lifetime bracket is ``now - before`` to ``now + after`` seconds,
    inside the 5 minutes either side of section 3.3 paragraph 1; both are this module's choices.
    Type covered, labels and original TTL are zero.
    """
    request = bytes(request)
    if len(request) < 12:
        raise Sig0Error("a DNS message is at least 12 octets")
    inception, expiration = now - before, now + after
    if inception < 0 or expiration > 0xFFFFFFFF:
        raise Sig0Error("the validity bracket does not fit the 32-bit fields")
    shell = RData_SIG(
        0, key.algorithm, 0, 0, expiration, inception, key_tag, signer, b"\x00"
    )  # a placeholder signature: only the fields before it are signed
    data = signed_data(shell.rdata_without_signature(), request)
    signature = sign(data, key)
    sig = RData_SIG(0, key.algorithm, 0, 0, expiration, inception, key_tag, signer, signature)
    return _with_extra_additional(request, bytes(_sig_rr(sig)))


@dataclass(frozen=True)
class Sig0Parts:
    """A message split at its SIG(0): the request as it was signed, and the SIG record."""

    request: bytes
    sig: RData_SIG
    record: DnsRecord


def split_sig0(message: bytes) -> Sig0Parts | None:
    """Split off a trailing SIG(0); ``None`` when the message does not end with one.

    A SIG(0) is "at the end of the query additional information section" with type covered zero
    (RFC 2931 section 3.1 paragraph 1). The returned request has ARCOUNT reduced by one, the form
    section 3.1 paragraph 2 says was signed. Sections are walked by offset, so a compressed
    signer name does not make the SIG look shorter or longer than it was.
    """
    message = bytes(message)
    if len(message) < 12:
        return None
    qd, an, ns, ar = struct.unpack_from("!4H", message, 4)
    if ar == 0:
        return None
    try:
        at = 12
        for _ in range(qd):
            _, at = DnsQuestion.parse(message, at)
        last_start = at
        last: DnsRecord | None = None
        for _ in range(an + ns + ar):
            last_start = at
            last, at = DnsRecord.parse(message, at)
    except DnsPacketParseError:
        return None
    if at != len(message) or last is None or int(last.rtype) != int(DnsRType.SIG):
        return None
    sig = last.rdata
    if not isinstance(sig, RData_SIG) or not sig.is_sig0:
        return None
    request = message[:10] + struct.pack("!H", ar - 1) + message[12:last_start]
    return Sig0Parts(request, sig, last)


def verify_request(
    message: bytes, key: VerifyKey, *, now: int, skew: int = MAX_SKEW_SECONDS
) -> bool:
    """True when ``message`` ends in a SIG(0) that verifies under ``key`` inside its lifetime.

    False for no SIG(0), a bad signature, an algorithm mismatch between the SIG and the key, or a
    bracket :func:`within_validity` refuses. A key that is not usable raises :class:`Sig0Error`,
    as :func:`verify` does. This does not decide whose key it is: that the signer owns a KEY
    equal to ``key`` is the registrar's check (RFC 9665 section 3.3.3).
    """
    parts = split_sig0(message)
    if parts is None:
        return False
    sig = parts.sig
    if sig.algorithm != key.algorithm:
        return False
    if not within_validity(sig.inception, sig.expiration, now, skew):
        return False
    data = signed_data(sig.rdata_without_signature(), parts.request)
    return verify(data, sig.signature, key)
