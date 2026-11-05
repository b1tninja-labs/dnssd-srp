"""registration domain enumeration and registrar SRV lookup (RFC 6763, RFC 9665 sec. 3.1.1).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    RegistrarEndpoint = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "registrar_from_zone",
]


def registrar_from_zone(zone_apex: str) -> RegistrarEndpoint:
    """Pending behaviour defined by RFC 9665 sec. 3.1.1.

    Not implemented yet. See the ``discovery.registrar_from_zone()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("registrar_from_zone() is not implemented: RFC 9665 sec. 3.1.1")
