"""SRP update construction (RFC 9665 sec. 3).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Lease = Any  # placeholder: give it a real type in the milestone that needs it
    ServiceDefinition = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "build_update",
]


def build_update(service: ServiceDefinition, lease: Lease) -> bytes:
    """Pending behaviour defined by RFC 9665 sec. 3.

    Not implemented yet. See the ``srp.build_update()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_update() is not implemented: RFC 9665 sec. 3")
