"""dnssd-srp -- DNS-SD without multicast.

The multicast answer to local service discovery already has a strong Python owner (zeroconf
0.153.0, 2026-10-31) and this project does not compete with it.
"""

from __future__ import annotations

from . import apps, cli, discovery, dso, lease, model, proxy, push, registrar, session, sig0, srp
from .discovery import registrar_from_zone
from .dso import decode_dso, encode_dso
from .push import subscribe
from .registrar import ttl_for, validate_update
from .session import open_session
from .sig0 import sign, verify
from .srp import build_update

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "build_update",
    "cli",
    "decode_dso",
    "discovery",
    "dso",
    "encode_dso",
    "lease",
    "model",
    "open_session",
    "proxy",
    "push",
    "registrar",
    "registrar_from_zone",
    "session",
    "sig0",
    "sign",
    "srp",
    "subscribe",
    "ttl_for",
    "validate_update",
    "verify",
]
