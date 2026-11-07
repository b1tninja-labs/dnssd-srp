# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation dnssd-srp could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `dso.encode_dso()` | RFC 8490 sec. 5.4 | `[ ]` | `tests/test_obligations.py::test_encode_dso` (to be written) | M1 |
| `session.open_session()` | RFC 8490 sec. 5.1, sec. 6 | `[ ]` | `tests/test_obligations.py::test_open_session` (to be written) | M1 |
| `srp.build_update()` | RFC 9665 sec. 3 | `[ ]` | `tests/test_obligations.py::test_build_update` (to be written) | M3 |
| `sig0.sign()` | RFC 2931, RFC 9665 sec. 6.6 | `[ ]` | `tests/test_obligations.py::test_sign` (to be written) | M2 |
| `sig0.verify()` | RFC 2931 | `[ ]` | `tests/test_obligations.py::test_verify` (to be written) | M2 |
| `registrar.validate_update()` | RFC 9665 sec. 3.3 | `[ ]` | `tests/test_obligations.py::test_validate_update` (to be written) | M4 |
| `registrar.ttl_for()` | RFC 9665 sec. 4 | `[ ]` | `tests/test_obligations.py::test_ttl_for` (to be written) | M4 |
| `push.subscribe()` | RFC 8765 sec. 6.2 | `[ ]` | `tests/test_obligations.py::test_subscribe` (to be written) | M5 |
| `discovery.registrar_from_zone()` | RFC 9665 sec. 3.1.1 | `[ ]` | `tests/test_obligations.py::test_registrar_from_zone` (to be written) | M3 |

## 2. Milestones

- M1 DSO codec and session with malformed-input refusal
- M2 SIG(0) sign and verify with the RFC 9665 sec. 6.6 algorithm
- M3 SRP requester: lease, TTL, keep-alive and teardown
- M4 registrar-side validation per RFC 9665 sec. 3.3, including the sec. 5 cleanup rules
- M5 push subscriptions, with erratum 8560 RECONFIRM behaviour
- M6 discovery proxy front end, then publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 8765 verified erratum 8560, sec. 6.5: for servers that do not implement RECONFIRM it MUST be silently ignored. The published text said a NOERROR response, which RFC 8490 forbids on a unidirectional DSO message.
- RFC 9665 and RFC 8490 report no errata as of 2026-10-29.
- RFC 6763 is updated by RFC 8553; RFC 6762 has 2 errata on file, none verified.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| an mDNS responder: zeroconf owns the multicast link | `[no]` | a named document requires it |
| a recursive resolver, which is what namespy is | `[no]` | a named document requires it |
| a full DNS server: the registrar half is the update path, not a zone implementation | `[no]` | a named document requires it |

## 5. Open questions

- share the DNS codec with namespy through a dependency, or keep a thin local layer
- how much of the registrar is a server rather than a validator
- M6 names a discovery proxy front end (RFC 8766), but no api row sits on it: add a proxy row, or drop the proxy from M6

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
