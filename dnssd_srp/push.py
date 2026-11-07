"""subscribe and replay protection (RFC 8765).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from typing import Any

    DsoSession = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "subscribe",
]


async def subscribe(session: DsoSession, name: str, rrtype: str) -> AsyncIterator:
    """Pending behaviour defined by RFC 8765 sec. 6.2.

    Not implemented yet. See the ``push.subscribe()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("subscribe() is not implemented: RFC 8765 sec. 6.2")
