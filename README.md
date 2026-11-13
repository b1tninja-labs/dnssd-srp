# dnssd-srp

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha.** The codecs and primitives are implemented and pinned by tests: the DSO message and
base TLVs (RFC 8490), the EDNS(0) Update Lease option (RFC 9664), SRP TTL consistency and policy
(RFC 9665 sec. 4) and ECDSA P-256 SIG(0) signing and verification (RFC 2931, RFC 6605). Everything
else is still a stub that raises `NotImplementedError`: the session, the SRP requester, the
registrar's update validation, push subscriptions and discovery. Which rows are which is in
[ROADMAP.md](ROADMAP.md); read it before depending on any of it.

Dependencies: [namespy](https://github.com/b1tninja/namespy), the DNS library this is built beside,
supplies the DNS message codec, the EDNS option layer and the name type (a sibling path dependency
until it is published); `cryptography` is an optional extra (`dnssd-srp[crypto]`) used for the ECDSA
P-256 signature primitive and nothing else. Both are explained in [docs/strategy.md](docs/strategy.md).

dnssd-srp -- DNS-SD without multicast

The multicast answer to local service discovery already has a strong Python owner (zeroconf 0.153.0, 2026-10-31) and this project does not compete with it. RFC 9665 moved DNS-SD to unicast authenticated updates in 2025-06, and RFC 8765 gave clients pushed record changes over a persistent stateful session. Nothing on PyPI speaks any of RFC 9665, RFC 8765, RFC 8490 or RFC 8766. namespy, the DNS library this is designed beside, states plainly that mDNS and DNS-SD are not spoken anywhere in it, so the message layer can be shared while the stateful half is built here.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| zeroconf | 0.153.0 | 2026-10-31 | the multicast responder; no SRP, no DSO, no push |
| dnspython | 2.9.2 | 2026-11-03 | message and DNSSEC plumbing; no stateful sessions |
| srp | 1.0.22 | 2024-11-01 | Secure Remote Password: an unrelated protocol wearing this acronym |
| dnssd-srp, srpkit, srpd, discovery-proxy | - | - | all absent from PyPI (2026-11-05) |

What this project intends to add:

- SRP update construction and the registrar-side validation of RFC 9665 sec. 3.3
- TTL consistency and lease maintenance rules, RFC 9665 sec. 4 and sec. 5
- SIG(0) signing with the algorithm RFC 9665 sec. 6.6 requires
- DSO session management: keepalive, idle timeout and padding (RFC 8490)
- push notification subscriptions (RFC 8765) and a discovery proxy front (RFC 8766)

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9665 | Proposed Standard | 2025-06 | SRP: unicast DNS-SD with SIG(0) defended registrations |
| RFC 8765 | Proposed Standard | 2020-06 | DNS Push Notifications for records that change |
| RFC 8490 | Proposed Standard | 2019-03 | DSO: the persistent session and TLV layer both ride |
| RFC 8766 | Proposed Standard | 2020-06 | discovery proxy bridging a link into unicast DNS-SD |
| RFC 2931 | Proposed Standard | 2000-09 | SIG(0) request signatures that defend a registration |
| RFC 6763 | Proposed Standard | 2013-02 | DNS-SD naming, plus the domain enumeration that finds a registrar |
| RFC 6762 | Proposed Standard | 2013-02 | mDNS, the world a discovery proxy bridges from |

### Errata watch

- RFC 8765 verified erratum 8560, sec. 6.5: for servers that do not implement RECONFIRM it MUST be silently ignored. The published text said a NOERROR response, which RFC 8490 forbids on a unidirectional DSO message.
- RFC 9665 and RFC 8490 report no errata as of 2026-10-29.
- RFC 6763 is updated by RFC 8553; RFC 6762 has 2 errata on file, none verified.

## Module layout

| Module | Responsibility |
|---|---|
| `dso` | DSO message and TLV codec, base TLVs (RFC 8490) |
| `lease` | EDNS(0) Update Lease option, 4- and 8-byte forms (RFC 9664 sec. 4) |
| `model` | plain data for the update path (`UpdateRR`), no wire format |
| `session` | stream transport, keepalive, idle timeout, padding (RFC 8490) |
| `srp` | SRP update construction (RFC 9665 sec. 3) |
| `registrar` | update validation and lease maintenance (RFC 9665 sec. 3.3, sec. 4, sec. 5) |
| `sig0` | SIG(0) sign and verify (RFC 2931, RFC 9665 sec. 6.6) |
| `push` | subscribe and replay protection (RFC 8765) |
| `proxy` | discovery proxy data translation (RFC 8766) |
| `discovery` | registration domain enumeration and registrar SRV lookup (RFC 6763, RFC 9665 sec. 3.1.1) |

## What it does not do

- an mDNS responder: zeroconf owns the multicast link
- a recursive resolver, which is what namespy is
- a full DNS server: the registrar half is the update path, not a zone implementation


## Install

```bash
git clone https://github.com/b1tninja/dnssd-srp.git
cd dnssd-srp
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy dnssd_srp tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
