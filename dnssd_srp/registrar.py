"""update validation and lease maintenance (RFC 9665 sec. 3.3, sec. 4, sec. 5).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ValidationOutcome = Any  # placeholder: give it a real type in the milestone that needs it
    ZoneContext = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "ttl_for",
    "validate_update",
]


def validate_update(update: bytes, zone: ZoneContext) -> ValidationOutcome:
    """Pending behaviour defined by RFC 9665 sec. 3.3.

    Not implemented yet. See the ``registrar.validate_update()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("validate_update() is not implemented: RFC 9665 sec. 3.3")


def ttl_for(lease_seconds: int) -> int:
    """Pending behaviour defined by RFC 9665 sec. 4.

    Not implemented yet. See the ``registrar.ttl_for()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("ttl_for() is not implemented: RFC 9665 sec. 4")
