"""DSO message and TLV codec, base TLVs (RFC 8490 sections 5.4 and 7).

Sans-IO: bytes in, a :class:`DsoMessage` out, and the reverse. The session timers that act on
these messages belong to :mod:`dnssd_srp.session`.

A DSO message is the twelve-byte DNS header with OPCODE 6 and all four counts zero, followed
by TLVs (RFC 8490 section 5.4). The header bits laid out by the section 5.4 figure are the
16-bit MESSAGE ID, then QR, the four OPCODE bits, seven Z bits and the four RCODE bits.

What the codec decides and what it leaves to the session:

* **Decides.** The header shape (opcode, counts), the TLV framing, and what the message is by
  its header alone: a *request* (QR 0, nonzero ID), a *unidirectional* message (QR 0, ID 0,
  section 5.4.3 paragraph 3) or a *response* (QR 1, nonzero ID). A response with ID 0 is
  refused as fatal (section 5.4.1 paragraph 5).
* **Leaves.** Whether a Primary TLV's type makes the message a request or a unidirectional one
  (section 5.4.1 paragraph 2: that is "determined only by the specification for the Primary
  TLV", so a request with ID 0 for a Keepalive is a session-level fatal error, not a framing
  error), what to do with an unrecognised TLV (section 5.4.5: ignore an Additional, answer
  DSOTYPENI to a Primary), and the timers. TLVs the codec does not know are kept, in order.

A :class:`DsoError` carries ``fatal`` (RFC 8490 says "forcibly abort the connection") and
``rcode`` (the response code the RFC says to return, when it names one), so the session
chooses between answering and aborting without parsing the message text.

Vectors: RFC 8490 publishes none. The tests build their bytes by hand from the figures and
say so.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

from namespy.enums import DnsOpCode, DnsQR, DnsResponseCode
from namespy.packet import DnsPacket
from namespy.wire import DnsPacketParseError

__all__ = [
    "DSO_OPCODE",
    "ENCRYPTION_PADDING",
    "KEEPALIVE",
    "MIN_KEEPALIVE_INTERVAL_MS",
    "RCODE_DSOTYPENI",
    "RCODE_FORMERR",
    "RCODE_NOERROR",
    "RCODE_NOTIMP",
    "RCODE_REFUSED",
    "RCODE_SERVFAIL",
    "RETRY_DELAY",
    "DsoError",
    "DsoMessage",
    "MessageKind",
    "Tlv",
    "decode_dso",
    "encode_dso",
    "keepalive_tlv",
    "padding_tlv",
    "parse_keepalive",
    "parse_retry_delay",
    "retry_delay_tlv",
]

#: RFC 8490 section 5.4.1 paragraph 6: the DSO OPCODE, which is namespy's ``DnsOpCode.DSO``
#: (RFC 8490 section 10.1). The header is namespy's too: see :func:`encode_dso`.
DSO_OPCODE = int(DnsOpCode.DSO)

#: DSO-TYPE registry, RFC 8490 section 10.3 (type 0 is reserved and never sent).
KEEPALIVE = 1
RETRY_DELAY = 2
ENCRYPTION_PADDING = 3

#: Response codes of section 5.4.1 paragraph 10.
RCODE_NOERROR = int(DnsResponseCode.NO_ERROR)
RCODE_FORMERR = int(DnsResponseCode.FORMAT_ERROR)
RCODE_SERVFAIL = int(DnsResponseCode.SERVER_FAILURE)
RCODE_NOTIMP = int(DnsResponseCode.NOT_IMPLEMENTED)
RCODE_REFUSED = int(DnsResponseCode.REFUSED)
RCODE_DSOTYPENI = int(DnsResponseCode.DSOTYPENI)  # RFC 8490 section 10.2

#: RFC 8490 section 7.1 paragraph 6: "The keepalive interval MUST NOT be less than ten seconds."
MIN_KEEPALIVE_INTERVAL_MS = 10_000

_HEADER_OCTETS = 12
_COUNTS = struct.Struct("!4H")  # QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, at offset 4
_TLV_HEAD = struct.Struct("!HH")
_U32_MAX = 0xFFFFFFFF
_U16_MAX = 0xFFFF


class DsoError(ValueError):
    """A DSO message that cannot be accepted.

    ``fatal`` is True where RFC 8490 says the recipient "MUST forcibly abort the connection
    immediately". ``rcode`` is the response code the RFC says to return when it names one
    (FORMERR for a nonzero count, section 5.4 paragraph 2), else ``None``.
    """

    def __init__(self, message: str, *, fatal: bool = False, rcode: int | None = None) -> None:
        super().__init__(message)
        self.fatal = fatal
        self.rcode = rcode


class MessageKind(Enum):
    """What a message is by its header alone (RFC 8490 sections 5.4.1 and 5.4.3)."""

    REQUEST = "request"
    UNIDIRECTIONAL = "unidirectional"
    RESPONSE = "response"


@dataclass(frozen=True)
class Tlv:
    """One TLV: a 16-bit DSO-TYPE and its opaque DSO-DATA (RFC 8490 section 5.4.4)."""

    dso_type: int
    data: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.dso_type <= _U16_MAX:
            raise ValueError(f"DSO-TYPE {self.dso_type} is outside 0..65535")
        if len(self.data) > _U16_MAX:
            raise ValueError(f"DSO-DATA of {len(self.data)} octets exceeds the 16-bit DSO-LENGTH")


@dataclass(frozen=True)
class DsoMessage:
    """A DSO message: header fields and TLVs in order. The Primary TLV is ``tlvs[0]``."""

    message_id: int
    qr: bool
    rcode: int = RCODE_NOERROR
    tlvs: tuple[Tlv, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.message_id <= _U16_MAX:
            raise ValueError(f"MESSAGE ID {self.message_id} is outside 0..65535")
        if not 0 <= self.rcode <= 15:
            raise ValueError(f"RCODE {self.rcode} does not fit the 4-bit header field")

    @property
    def kind(self) -> MessageKind:
        """Request, unidirectional or response, from QR and MESSAGE ID alone."""
        if self.qr:
            return MessageKind.RESPONSE
        return MessageKind.REQUEST if self.message_id else MessageKind.UNIDIRECTIONAL

    @property
    def primary(self) -> Tlv | None:
        """The Primary TLV (section 5.4.2 paragraph 2), or ``None`` when there are no TLVs."""
        return self.tlvs[0] if self.tlvs else None


def encode_dso(message: DsoMessage) -> bytes:
    """Serialise a DSO message (RFC 8490 sec. 5.4).

    The header is written with OPCODE 6, the Z bits zero ("MUST be set to zero on
    transmission", section 5.4.1 paragraph 7) and every count zero (section 5.4 paragraph 1).
    Refuses what the RFC forbids a sender: a request or unidirectional message with no TLV
    (section 5.4.2 paragraph 2), a response with MESSAGE ID 0 (section 5.4.1 paragraph 5), and
    DSO-TYPE 0, which section 10.3 reserves.
    """
    if not message.qr and not message.tlvs:
        raise DsoError("a DSO request or unidirectional message needs at least one TLV (5.4.2)")
    if message.qr and message.message_id == 0:
        raise DsoError("a DSO response needs a nonzero MESSAGE ID (5.4.1)", fatal=True)
    # The header is the shared codec's: a DnsPacket with every flag clear except QR, OPCODE and
    # RCODE and no sections serialises to the twelve octets of RFC 8490 section 5.4 (the Z bits,
    # AA, TC, RD, RA, AD and CD are all zero, which is what "MUST be set to zero" asks).
    header = DnsPacket(
        message.message_id,
        QR=DnsQR.RESPONSE if message.qr else DnsQR.QUERY,
        OPCODE=DnsOpCode.DSO,
        RD=False,
        RCODE=message.rcode,
    )
    out = bytearray(bytes(header))
    for tlv in message.tlvs:
        if tlv.dso_type == 0:
            raise DsoError("DSO-TYPE 0 is reserved and is not sent (RFC 8490 section 10.3)")
        out += _TLV_HEAD.pack(tlv.dso_type, len(tlv.data)) + tlv.data
    return bytes(out)


def decode_dso(data: bytes) -> DsoMessage:
    """Parse a DSO message, refusing what RFC 8490 sec. 5.4 refuses.

    Raises :class:`DsoError` for a message shorter than the header, an OPCODE other than 6, a
    nonzero count (``rcode`` FORMERR, section 5.4 paragraph 2), a TLV header or body that runs
    past the message, a request or unidirectional message with no TLV, and a response with
    MESSAGE ID 0 (``fatal``, section 5.4.1 paragraph 5). Z bits are ignored. Unknown TLVs, and
    a DSO-TYPE of 0, are kept in order: ignoring them is the session's decision (section 5.4.5).
    """
    data = bytes(data)
    if len(data) < _HEADER_OCTETS:
        raise DsoError(f"DSO message of {len(data)} octets is shorter than the 12-octet header")
    # The counts are read by hand and zeroed before the shared parser sees the header: with a
    # nonzero count it would go looking for sections, and RFC 8490 section 5.4 paragraph 2 wants
    # FORMERR, not a parse error.
    qd, an, ns, ar = _COUNTS.unpack_from(data, 4)
    try:
        header, _ = DnsPacket.parse(data[:4] + bytes(8))
    except DnsPacketParseError as exc:  # pragma: no cover - twelve octets always parse
        raise DsoError(f"unreadable DSO header: {exc}") from exc
    opcode = int(header.OPCODE)
    if opcode != DSO_OPCODE:
        raise DsoError(f"OPCODE {opcode} is not the DSO OPCODE ({DSO_OPCODE})")
    if qd or an or ns or ar:
        raise DsoError(
            f"DSO counts must all be zero, got QD={qd} AN={an} NS={ns} AR={ar} (5.4)",
            rcode=RCODE_FORMERR,
        )
    message_id = header.ID
    qr = int(header.QR) == int(DnsQR.RESPONSE)
    tlvs: list[Tlv] = []
    offset = _HEADER_OCTETS
    while offset < len(data):
        if len(data) - offset < _TLV_HEAD.size:
            raise DsoError(f"{len(data) - offset} stray octet(s) where a TLV header should be")
        dso_type, length = _TLV_HEAD.unpack_from(data, offset)
        offset += _TLV_HEAD.size
        if length > len(data) - offset:
            raise DsoError(
                f"TLV type {dso_type} declares {length} octets but only {len(data) - offset} remain"
            )
        tlvs.append(Tlv(dso_type, data[offset : offset + length]))
        offset += length
    if qr and message_id == 0:
        raise DsoError("a DSO response with MESSAGE ID 0 is a fatal error (5.4.1)", fatal=True)
    if not qr and not tlvs:
        raise DsoError("a DSO request or unidirectional message has no TLV (5.4.2)")
    return DsoMessage(message_id, qr, int(header.RCODE), tuple(tlvs))


def _u32(value: int, what: str) -> int:
    if not 0 <= value <= _U32_MAX:
        raise ValueError(f"{what} {value} is outside 0..2**32-1")
    return value


def keepalive_tlv(inactivity_ms: int, keepalive_ms: int) -> Tlv:
    """The Keepalive TLV: INACTIVITY TIMEOUT then KEEPALIVE INTERVAL, 32 bits each (7.1).

    Refuses an interval under ten seconds, which RFC 8490 section 7.1 paragraph 6 forbids.
    """
    if keepalive_ms < MIN_KEEPALIVE_INTERVAL_MS:
        raise ValueError(f"keepalive interval {keepalive_ms} ms is under the 10000 ms minimum")
    return Tlv(
        KEEPALIVE,
        struct.pack(
            "!II", _u32(inactivity_ms, "inactivity timeout"), _u32(keepalive_ms, "interval")
        ),
    )


def parse_keepalive(tlv: Tlv) -> tuple[int, int]:
    """``(inactivity_ms, keepalive_interval_ms)`` from a Keepalive TLV (RFC 8490 section 7.1)."""
    if tlv.dso_type != KEEPALIVE:
        raise DsoError(f"TLV type {tlv.dso_type} is not Keepalive")
    if len(tlv.data) != 8:
        raise DsoError(f"Keepalive DSO-DATA is {len(tlv.data)} octets, must be 8 (7.1)")
    inactivity, interval = struct.unpack("!II", tlv.data)
    if interval < MIN_KEEPALIVE_INTERVAL_MS:
        raise DsoError(f"keepalive interval {interval} ms is under the 10000 ms minimum (7.1)")
    return inactivity, interval


def retry_delay_tlv(delay_ms: int) -> Tlv:
    """The Retry Delay TLV: one 32-bit millisecond value (RFC 8490 section 7.2)."""
    return Tlv(RETRY_DELAY, struct.pack("!I", _u32(delay_ms, "retry delay")))


def parse_retry_delay(tlv: Tlv) -> int:
    """The delay in milliseconds from a Retry Delay TLV (RFC 8490 section 7.2)."""
    if tlv.dso_type != RETRY_DELAY:
        raise DsoError(f"TLV type {tlv.dso_type} is not Retry Delay")
    if len(tlv.data) != 4:
        raise DsoError(f"Retry Delay DSO-DATA is {len(tlv.data)} octets, must be 4 (7.2)")
    return int(struct.unpack("!I", tlv.data)[0])


def padding_tlv(length: int, fill: int = 0) -> Tlv:
    """The Encryption Padding TLV with ``length`` filler octets, 0x00 by default (7.3).

    A length of 0 is legal and "essentially provides for 4 bytes of padding" (the TLV header).
    Received padding of any value must be accepted, which the decoder does by never reading it.
    """
    if length < 0 or length > _U16_MAX:
        raise ValueError(f"padding length {length} is outside 0..65535")
    if not 0 <= fill <= 255:
        raise ValueError(f"padding fill {fill} is not an octet")
    return Tlv(ENCRYPTION_PADDING, bytes([fill]) * length)
