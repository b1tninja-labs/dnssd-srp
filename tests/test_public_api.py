"""The shell contract: the surface exists, is documented, and refuses to lie.

These are the tests that must fail loudly if a stub ever starts returning a plausible
empty value instead of raising. That is how a protocol library quietly becomes wrong: a
decoder learns to return an empty object rather than refuse, and every caller downstream
reads confidence where there was only silence.
"""

from __future__ import annotations

import importlib

import pytest

import dnssd_srp as package

SURFACE = [
    ("dso", "encode_dso", "RFC 8490 sec. 5.4"),
    ("session", "open_session", "RFC 8490 sec. 5.1, sec. 6"),
    ("srp", "build_update", "RFC 9665 sec. 3"),
    ("sig0", "sign", "RFC 2931, RFC 9665 sec. 6.6"),
    ("sig0", "verify", "RFC 2931"),
    ("registrar", "validate_update", "RFC 9665 sec. 3.3"),
    ("registrar", "ttl_for", "RFC 9665 sec. 4"),
    ("push", "subscribe", "RFC 8765 sec. 6.2"),
    ("discovery", "registrar_from_zone", "RFC 9665 sec. 3.1.1"),
]


#: Implemented and pinned by their own test files; the stub contract below no longer applies.
IMPLEMENTED = {
    ("dso", "encode_dso"),
    ("registrar", "ttl_for"),
    ("sig0", "sign"),
    ("sig0", "verify"),
    ("srp", "build_update"),
    ("registrar", "validate_update"),
}
STUBS = [row for row in SURFACE if row[:2] not in IMPLEMENTED]


def test_version_is_a_string():
    assert isinstance(package.__version__, str)


def test_public_names_all_exist():
    missing = [name for name in package.__all__ if not hasattr(package, name)]
    assert not missing, "__all__ names things that do not exist: " + ", ".join(missing)


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_surface_is_documented(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    assert target.__doc__, fn + " needs a docstring"
    # Docstrings are wrapped, so a long citation can span a line break; compare words, not layout.
    assert " ".join(cite.split()) in " ".join(target.__doc__.split()), (
        fn + " must cite the document that defines it"
    )


@pytest.mark.parametrize(("module_name", "fn", "cite"), STUBS)
def test_stubs_are_loud(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    if "Not implemented yet" not in (target.__doc__ or ""):
        pytest.skip(fn + " is implemented; pin it with a real vector test now")
    with pytest.raises((NotImplementedError, TypeError)):
        target()
