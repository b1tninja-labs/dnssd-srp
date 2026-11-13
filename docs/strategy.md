# Strategy

The completeness matrix is [../ROADMAP.md](../ROADMAP.md). This document is *why* the rows
are ordered the way they are, and the rules that order has to respect.

## The constitution

1. **The core is the specification implementation.** `dnssd_srp/` holds codecs, state machines
   and the vocabulary of dnssd-srp. New core code appears when a document defines the
   behaviour, or when an ordering rule with no document earns an explicit convention label.
2. **Sans-IO before sockets.** Anything decidable from data plus a clock is implemented
   without touching a socket, so every timeout, retry and rollover is testable without
   sleeping or networking.
3. **Dependency-free by default.** An exception needs a sentence in README.md explaining why
   the rule was broken, and a floor with no ceiling.
4. **Positioning is correctness and legibility, not throughput.** The incumbents in this
   corner are usually stale, untyped, or welded to a product. This is the implementation that
   says how it knows what it claims.
5. **Every answer carries its provenance.** Verified or cached, which document, refused or
   believed. An answer without provenance is a guess with a confident type.

## Dependencies

The package declares one runtime dependency, **namespy**, and one optional one, **cryptography**
(the `crypto` extra).

- **namespy.** An SRP Update is a DNS Update (RFC 2136) carrying an EDNS(0) option (RFC 9664) and
  a SIG(0) record (RFC 2931), and a DSO session rides the same stream framing as any DNS message. The
  standard library has none of that, and writing a second DNS codec beside namespy's would give
  the portfolio two parsers of the same wire format to keep correct. So the message codec, the
  OPT/option layer and the name type are namespy's, consumed as a sibling path dependency
  (`pythonpath` and `mypy_path` in `pyproject.toml`) until namespy is published. What this
  project adds is the stateful half: DSO, leases, registrar rules and SIG(0). Where namespy lacks a
  codec this project needs (`DnsOpCode.DSO`, a SIG codec, a KEY codec), the codec is added to
  namespy, and the ROADMAP row `dns.namespy-gaps` says so; it is not rebuilt here.
- **cryptography.** SIG(0) needs ECDSA P-256 (RFC 6605 algorithm 13), which is a signature
  primitive. The portfolio rule (`PORTFOLIO.md` section 9 item 15) allows `cryptography` for those
  and for nothing else, so it supplies the curve arithmetic and every wire format around it stays
  ours. It is an extra because only a signer or a verifier needs it, and a DSO codec should not.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `dnssd_srp/` | codecs, state machines, policy objects | RFC-cited or convention-labelled |
| Apps | `dnssd_srp/apps/` | reusable assemblies that compose core | no new protocol surface |
| Examples | `examples/` | one runnable script per use case | configures; never restates logic |

## Interface grammar

One engine, three drives, never parallel implementations:

- **await** -- the native asyncio surface.
- **blocking** -- a facade owning a private loop, so a call from inside a caller's running
  loop works instead of deadlocking.
- **callback** -- plain callables, no third-party promise type.

## Naming

One string everywhere: the distribution, the import and the console script. A name that
means one thing in the installer, in `import` and on `PATH` is the only arrangement that
cannot surprise anyone, and it is also why this project does not sit one edit away from a
project that already exists.
