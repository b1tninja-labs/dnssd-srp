"""DSO message and TLV codec, session timers (RFC 8490).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    DsoMessage = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "encode_dso",
]


def encode_dso(message: DsoMessage) -> bytes:
    """Pending behaviour defined by RFC 8490 sec. 5.4.

    Not implemented yet. See the ``dso.encode_dso()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_dso() is not implemented: RFC 8490 sec. 5.4")
