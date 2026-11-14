"""The registrar's refusal of TCP Fast Open payloads (RFC 9665 section 6.1).

"For TCP updates, the initial SYN-SYN+ACK handshake prevents updates being forged by an off-path
attacker. In order to ensure that this handshake happens, SRP registrars relying on
three-way-handshake validation MUST NOT accept TCP Fast Open payloads [RFC7413]. If the network
infrastructure allows it, an SRP registrar MAY accept TCP Fast Open payloads if all such packets
are validated along the path, and the network is able to reject this type of spoofing at all
ingress points." (RFC 9665 section 6.1 paragraph 2.)

Two pieces, both small:

* :func:`accept_fast_open_payload` is the decision. The default is the MUST NOT; the MAY needs the
  operator to say that the network validates every such packet and rejects spoofing at every
  ingress, which this library cannot check and does not assume;
* :func:`refuse_fast_open` acts on a listening TCP socket: a server accepts data in a SYN only when
  the listening socket has asked for it with ``TCP_FASTOPEN``, so the registrar's listener is
  given the option set to zero and the value is read back. It reports what it found rather than
  assuming: a platform without the option cannot accept the payloads through this socket.
"""

from __future__ import annotations

import enum
import socket

__all__ = [
    "FastOpenState",
    "accept_fast_open_payload",
    "refuse_fast_open",
]


class FastOpenState(enum.Enum):
    """What :func:`refuse_fast_open` left the listener in."""

    DISABLED = "disabled"  # the option exists and reads back zero
    UNAVAILABLE = "unavailable"  # this platform has no TCP_FASTOPEN socket option to set


def accept_fast_open_payload(*, path_validated: bool = False) -> bool:
    """Whether a registrar may accept data carried in a TCP SYN (RFC 9665 section 6.1 paragraph 2).

    ``path_validated`` is the operator's statement that every such packet is validated along the
    path and that the network rejects this spoofing at all ingress points. Without it the answer is
    False: the registrar relies on the three-way handshake.
    """
    return bool(path_validated)


def refuse_fast_open(listener: socket.socket) -> FastOpenState:
    """Make ``listener`` refuse TCP Fast Open payloads, and say whether that is verified.

    Raises :class:`OSError` when the platform has the option but the socket refuses to be set to
    zero, or reads back non-zero afterwards: a registrar must not continue as if it were safe.
    """
    option = getattr(socket, "TCP_FASTOPEN", None)
    if option is None:
        return FastOpenState.UNAVAILABLE
    listener.setsockopt(socket.IPPROTO_TCP, option, 0)
    if listener.getsockopt(socket.IPPROTO_TCP, option) != 0:
        raise OSError(
            "the listener still accepts TCP Fast Open payloads after the option was cleared"
        )
    return FastOpenState.DISABLED
