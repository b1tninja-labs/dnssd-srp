# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- SRP over namespy's codecs: `sig0.sign_request`, `verify_request` and `split_sig0` (the SIG(0)
  record is `namespy.rdata.RData_SIG`, the key `RData_KEY`); `srp.build_update` and
  `srp.update_message`; `registrar.classify_update`, `check_fcfs`, `check_signature` and
  `validate_update` (RFC 9665 sec. 3.2 and 3.3). The DSO header now comes from namespy's `DnsPacket`.
- `dso`: `encode_dso` and `decode_dso` for the RFC 8490 sec. 5.4 message, with the refusal rules
  (nonzero counts, truncated or overrunning TLVs, a response with ID 0), and the Keepalive, Retry
  Delay and Encryption Padding TLVs of sec. 7.
- `lease`: the RFC 9664 sec. 4 Update Lease option in both forms, the sec. 4.3 response-variant
  rule, and the bridge to `namespy.edns.EdnsOption`.
- `registrar.check_ttl_consistency` and `registrar.ttl_for` (RFC 9665 sec. 4); `model.UpdateRR`.
- `sig0`: ECDSA P-256 `sign` and `verify`, `signed_data` and `within_validity` (RFC 2931, RFC 6605
  sec. 4), checked against the RFC 6605 sec. 6.1 vector.
- `namespy` as a sibling path dependency, and `cryptography` as the `crypto` extra for the
  signature primitive only.

The rest of the public surface is still stubs that raise `NotImplementedError`;
[ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for dnssd-srp.
- `dnssd_srp.apps` namespace reserved for composition that is not protocol behaviour.
