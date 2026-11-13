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
| `dso.encode_dso()` | RFC 8490 sec. 5.4 | `[ok]` | `tests/test_dso.py::test_header_is_twelve_bytes_opcode_six`, `tests/test_dso.py::test_request_with_zero_tlvs_refused_both_ways`, `tests/test_dso.py::test_z_bits_ignored_on_decode_zero_on_encode` | M1 |
| `dso.decode_dso()` | RFC 8490 sec. 5.4 | `[ok]` | `tests/test_dso.py::test_decode_rejects_nonzero_counts`, `tests/test_dso.py::test_decode_rejects_truncated_tlv_header`, `tests/test_dso.py::test_decode_rejects_length_overrun`, `tests/test_dso.py::test_response_with_zero_id_is_fatal`, `tests/test_dso.py::test_decode_never_returns_garbage_on_random_bytes`. No published vector exists: the bytes are hand-built from the section 5.4 figures and the tests say so | M1 |
| `dso.keepalive_tlv()` | RFC 8490 sec. 7.1 | `[ok]` | `tests/test_dso.py::test_keepalive_interval_below_ten_seconds_refused_on_parse_and_build`, `tests/test_dso.py::test_roundtrip_all_three_base_tlvs` | M1 |
| `dso.retry_delay_tlv()` | RFC 8490 sec. 7.2 | `[ok]` | `tests/test_dso.py::test_u32_bounds`, `tests/test_dso.py::test_keepalive_and_retry_delay_bodies_have_fixed_sizes` | M1 |
| `dso.padding_tlv()` | RFC 8490 sec. 7.3 | `[ok]` | `tests/test_dso.py::test_padding_of_any_value_is_accepted_and_zero_length_is_legal` | M1 |
| `session.open_session()` | RFC 8490 sec. 5.1, sec. 6 | `[ ]` | `tests/test_session.py::test_open_session` (to be written) | M1 |
| `session.timers` | RFC 8490 sec. 6.2 to sec. 6.5, sec. 7.1, sec. 7.1.1: inactivity and keepalive timers on a virtual clock (keepalive traffic resets only the keepalive timer, sec. 7.1 paragraph 7; a lowered inactivity timeout takes effect at once, sec. 7.1.1) | `[ ]` | `tests/test_session_timers.py::test_keepalive_does_not_reset_inactivity` (to be written) | M1 |
| `session.primary-tlv-rules` | RFC 8490 sec. 5.4.1 paragraph 2, sec. 5.4.3 paragraph 3, sec. 5.4.5, sec. 7.1 paragraphs 8 and 10, sec. 7.2.1 paragraph 13: whether a message may be a request or unidirectional is the Primary TLV's, so a Keepalive request with ID 0, a server Keepalive with a nonzero ID and a client Retry Delay are fatal, an unknown Primary TLV earns DSOTYPENI (never, when the ID is 0), an unknown Additional TLV is ignored | `[ ]` | `tests/test_session_rules.py::test_keepalive_request_with_zero_id_is_fatal` (to be written) | M1 |
| `session.retry-delay-handling` | RFC 8490 sec. 6.6, sec. 7.2: terminate on a Retry Delay message, never reconnect inside the delay, a Retry Delay on an error response applies to that operation only | `[ ]` | `tests/test_session_retry.py::test_no_reconnect_inside_the_retry_delay` (to be written) | M1 |
| `session.no-edns-keepalive` | RFC 8490 sec. 7.1.2, sec. 5.4.6 paragraph 5: an edns-tcp-keepalive option anywhere on a DSO session is fatal | `[ ]` | `tests/test_session_rules.py::test_edns_keepalive_on_a_dso_session_is_fatal` (to be written) | M1 |
| `session.transport` | RFC 8490 sec. 5.1, RFC 7858 (registrars MUST offer TLS, RFC 9665 sec. 7: not re-read): the stream/TLS leg over asyncio, no sockets in the codec | `[ ]` | `tests/test_session_transport.py::test_loopback_tls_session` (to be written) | M1 |
| `lease.encode_update_lease()` | RFC 9664 sec. 4 | `[ok]` | `tests/test_lease.py::test_four_byte_form_bytes`, `tests/test_lease.py::test_eight_byte_form_bytes`, `tests/test_lease.py::test_u32_bounds` | M3 |
| `lease.decode_update_lease()` | RFC 9664 sec. 4 | `[ok]` | `tests/test_lease.py::test_decode_rejects_length_other_than_4_or_8`, `tests/test_lease.py::test_decode_rejects_wrong_option_code`, `tests/test_lease.py::test_decode_rejects_declared_length_beyond_buffer`, `tests/test_lease.py::test_lease_greater_than_key_lease_flagged` | M3 |
| `lease.response_variant()` | RFC 9664 sec. 4.3 paragraphs 3 and 4: an 8-byte request is answered in 8 bytes, a 4-byte request in 4 | `[ok]` | `tests/test_lease.py::test_server_answers_in_the_requesters_variant` | M4 |
| `lease.from_edns_options()` | RFC 9664 sec. 4.2 paragraph 2: an absent option is information, not a default | `[ok]` | `tests/test_lease.py::test_absent_option_is_none_not_a_default`, `tests/test_lease.py::test_edns_option_roundtrip_through_the_shared_codec` | M3 |
| `srp.build_update()` | RFC 9665 sec. 3 (sec. 3.2.5.1 paragraphs 4 to 6, sec. 3.2.5.5.1, sec. 3.3.1): the requester side, over namespy's `DnsPacket`: Service Discovery PTRs, then per instance a delete-all, SRV and TXT adds (the host KEY omitted unless `repeat_service_keys`), then the Host Description (delete-all, KEY with flags zero, A and AAAA adds), the OPT with the Update Lease, a SIG(0) last. A removal has no addresses and needs LEASE zero; every added RR has one TTL | `[ok]` | `tests/test_srp_message.py::test_build_update`, `tests/test_srp_message.py::test_update_message_round_trips_through_namespy`, `tests/test_srp_message.py::test_the_service_key_is_omitted_by_default_and_repeatable`, `tests/test_srp_message.py::test_a_removal_needs_lease_zero_and_keeps_the_key` | M3 |
| `srp.update-message` | RFC 2136 sec. 2 (OPCODE 5; one erratum, 4469, on sec. 3.4.2.2, not this row) and RFC 9665 sec. 3.3.1: `update_message(packet)` reduces a parsed namespy `DnsPacket` to `UpdateMessage` (zone SOA IN, the four update forms of sec. 2.5 by CLASS and TYPE, PRCOUNT, the Update Lease option) and refuses what RFC 2136 sec. 2.3 calls FORMERR. No second codec | `[ok]` | `tests/test_srp_message.py::test_update_message_round_trips_through_namespy`, `tests/test_srp_message.py::test_update_message_rejects_what_rfc2136_calls_formerr` | M3 |
| `srp.requester-uses-granted-lease` | RFC 9665 sec. 5.1 paragraph 6, RFC 9664 sec. 4.2 paragraph 3: renew on the lease in the response, shorter or longer; a response with no option is treated as if the server had echoed the request | `[ ]` | `tests/test_srp.py::test_requester_renews_on_the_granted_lease` (to be written) | M3 |
| `srp.registration-jitter` | RFC 9664 sec. 4.2 paragraph 4: delay the first Registration Request by a random 0 to 3000 ms at no coarser than 10 ms. **Found 2026-11-13; the research round missed it.** The delay takes an injected RNG and clock | `[ ]` | `tests/test_srp.py::test_initial_registration_delay_is_0_to_3000_ms_in_10_ms_steps` (to be written) | M3 |
| `srp.requester-rules` | RFC 9665 sec. 3.2.3.3 paragraph 1 (one update in flight), sec. 3.2.5.1 paragraph 6 (an omitted service KEY inherits the host KEY and is not signed over), sec. 6.1 paragraph 2 (no TCP Fast Open payloads). **Paragraph references come from the 2026-11-12 research and were not re-read in this pass; read each section before coding** | `[ ]` | `tests/test_srp.py` (to be written) | M3 |
| `sig0.sign()` | RFC 2931, RFC 9665 sec. 6.6 | `[ok]` | `tests/test_sig0.py::test_rfc6605_private_key_belongs_to_the_published_dnskey`, `tests/test_sig0.py::test_signature_does_not_cover_a_different_request`, `tests/test_sig0_rr.py::test_signature_is_over_rdata_then_the_unadjusted_request`. ECDSA P-256 (algorithm 13) only, returning the 64-octet r\|s, with `cryptography` as the primitive under the portfolio rule. `sign_request` appends the SIG(0). Other algorithms are `sig0.algorithm-set` | M2 |
| `sig0.verify()` | RFC 2931, RFC 6605 sec. 4 | `[ok]` | `tests/test_sig0.py::test_verify_rfc6605_p256_rrsig_vector`, `tests/test_sig0.py::test_flipped_bit_in_message_rejected`, `tests/test_sig0.py::test_unsupported_algorithm_refused_not_true`, `tests/test_sig0.py::test_r_or_s_zero_or_ge_order_rejected`, `tests/test_sig0_rr.py::test_a_flipped_bit_anywhere_in_the_request_fails`. The independent vector is RFC 6605 sec. 6.1, which proves the primitive and not the SIG(0) construction; `verify_request` checks a message's trailing SIG(0). Arithmetic is `namespy.crypto.verify_dnskey_signature` | M2 |
| `sig0.signed_data()` | RFC 2931 sec. 3.1 paragraph 3 (data = RDATA \| request - SIG(0)) | `[ok]` | `tests/test_sig0.py::test_signed_data_is_rdata_then_request_in_that_order`, `tests/test_sig0.py::test_signature_does_not_cover_a_different_request` | M2 |
| `sig0.within_validity()` | RFC 2931 sec. 3.3 paragraph 1: the lifetime bracket is at most 5 minutes either side | `[ok]` | `tests/test_sig0.py::test_expired_and_not_yet_valid_rejected_with_clock_argument`, `tests/test_sig0.py::test_validity_bracket_wider_than_five_minutes_is_refused_and_configurable` | M2 |
| `sig0.sig-rr` | RFC 2931 sec. 3 paragraphs 1 and 3 keep the SIG layout of RFC 2535 sec. 4.1 normative although **RFC 2535 is obsolete**. The record is namespy's `RData_SIG` (decided: namespy owns every DNS codec): type covered 0, owner root, class ANY, TTL 0, lifetime inside 5 minutes either side. **Correction:** RFC 2931 sec. 3 paragraph 3 makes root owner, class ANY and zero TTLs `SHOULD`, not `MUST`; this builder does all three and a verifier does not insist | `[ok]` | `tests/test_sig0_rr.py::test_sig0_rr_layout`, `tests/test_sig0_rr.py::test_the_sig0_is_last_and_arcount_counts_it`, `tests/test_sig0_rr.py::test_split_returns_the_request_as_it_was_signed`, `tests/test_sig0_rr.py::test_a_sig_that_covers_a_type_is_not_a_sig0` | M2 |
| `sig0.algorithm-set` | RFC 9665 sec. 6.6 says registrars SHOULD implement the algorithms numbered 13 or higher that RFC 8624 sec. 3.1 marks MUST, RECOMMENDED or MAY for validation. **RFC 8624 is obsolete: RFC 9904 (2025-11) moved the canonical table to the IANA DNSSEC algorithm registries** (RFC 9904 sec. 1 paragraph 2). The SHOULD set is therefore read from the IANA registry, fetched by the owner and dated, not from a table in an RFC. The MUST (algorithm 13) is unaffected | `[ ]` | `tests/test_sig0_algorithms.py::test_should_set_comes_from_a_dated_registry_snapshot` (to be written) | M2 |
| `registrar.validate_update()` | RFC 9665 sec. 3.3: parse (FORMERR), zone (NOTZONE), classify (not an SRP Update is REFUSED, plain updates are not processed, which sec. 3.3.2 paragraph 3 allows), TTL consistency (REFUSED), FCFS (YXDOMAIN), SIG(0) (REFUSED). Applying the update, leases and the response message are not done | `[ok]` | `tests/test_srp_message.py::test_validate_update_accepts_a_valid_update`, `tests/test_srp_message.py::test_validate_update_maps_each_failure_to_the_rcode_the_rfc_names`, `tests/test_srp_message.py::test_validate_update_refuses_what_is_not_an_srp_update` | M4 |
| `model.update-message` | RFC 9665 sec. 3.3.1: plain dataclasses (`UpdateOp`, `OpKind`, `UpdateMessage`, `UpdateRR`) so `registrar` rules do not wait for the codec; `srp.update_message` fills them from a namespy packet | `[ok]` | `tests/test_srp_message.py::test_update_message_round_trips_through_namespy`, `tests/test_registrar_ttl.py::test_rrset_key_is_name_and_type_case_insensitive` | M4 |
| `registrar.classify-update` | RFC 9665 sec. 3.3.1 to sec. 3.3.2, all read: exactly one Host Description (one delete-all, one KEY add, A and AAAA adds only), Service Description (one delete-all, at most one KEY equal to the host's, SRV targeting the host and TXT together or neither), Service Discovery (a PTR add needs an SRV instance, a PTR delete one without), delete-all before adds, names in the zone, no prerequisites, an Update Lease with LEASE at most KEY-LEASE; else `NotSrp(reason)`. **Spec finding:** sec. 3.2.5.5.1 paragraph 1 says a host removal has "no Add to an RRSet instructions" but sec. 3.3.1.3 paragraph 3 requires exactly one KEY add in every Host Description; both cannot hold. The classifier follows sec. 3.3.1.3, because the KEY is what the SIG(0) is checked against. Also: sec. 3.2.1 paragraph 3 says the KEY RR is defined by RFC 2539 and sec. 3.2.5.1 paragraph 5 and sec. 3.3.3 paragraph 4 say RFC 4034 (which defines DNSKEY flags, not KEY) | `[ok]` | `tests/test_srp_message.py::test_a_requesters_update_classifies_as_an_srp_update`, `tests/test_srp_message.py::test_two_host_descriptions_is_not_an_srp_update`, `tests/test_srp_message.py::test_prerequisites_make_it_not_an_srp_update`, `tests/test_srp_message.py::test_no_lease_option_or_lease_above_key_lease_is_not_an_srp_update`, `tests/test_srp_message.py::test_delete_all_must_precede_the_adds_for_its_name`, `tests/test_srp_message.py::test_srv_target_must_be_the_host`, `tests/test_srp_message.py::test_deleting_a_service_pairs_a_ptr_delete_with_a_bare_delete_all` | M4 |
| `registrar.key-and-signature-checks` | RFC 9665 sec. 3.3.3: `check_fcfs` returns YXDOMAIN for a stored KEY that differs from the update's (an omitted service KEY is the host's), `check_signature` returns REFUSED unless the SIG(0) verifies under the host KEY and for any algorithm but 13. KEY flags are carried as received by `RData_KEY`; storing them is the zone's, not done here | `[part]` | `tests/test_srp_message.py::test_a_different_key_for_an_owned_name_is_yxdomain`, `tests/test_srp_message.py::test_a_valid_signature_passes_and_a_tampered_update_is_refused`, `tests/test_srp_message.py::test_a_key_of_another_algorithm_cannot_be_checked_and_is_refused` | M4 |
| `registrar.atomic-service-update` | RFC 9665 sec. 3.3.4: a service and its subtypes are updated together | `[ ]` | `tests/test_registrar_atomic.py` (to be written; sec. 3.3.4 not re-read) | M4 |
| `registrar.lease-expiry` | RFC 9665 sec. 5.1 paragraphs 4 and 5 (read in this pass): expiry of the host lease removes the host, its services and their PTRs together; a lease is also tracked per service instance, whose KEY outlives it until the KEY lease | `[ ]` | `tests/test_registrar_expiry.py::test_host_lease_expiry_removes_dependent_services` (to be written) | M4 |
| `registrar.check_ttl_consistency()` | RFC 9665 sec. 4 paragraphs 2 and 3 | `[ok]` | `tests/test_registrar_ttl.py::test_two_ptr_records_different_ttl_refused`, `tests/test_registrar_ttl.py::test_different_rrsets_may_have_different_ttls`, `tests/test_registrar_ttl.py::test_rrset_key_is_name_and_type_case_insensitive` | M4 |
| `registrar.ttl_for()` | RFC 9665 sec. 4 paragraph 5 (replaces the old `ttl_for(lease_seconds)` row: nothing in sec. 4 defines a TTL as a function of the lease alone) | `[ok]` | `tests/test_registrar_ttl.py::test_ttl_never_exceeds_lease`, `tests/test_registrar_ttl.py::test_ttl_clamped_to_policy_bounds`, `tests/test_registrar_ttl.py::test_lease_shorter_than_minimum_wins` | M4 |
| `push.subscribe()` | RFC 8765 sec. 6.2 | `[ ]` | `tests/test_push.py::test_subscribe` (to be written) | M5 |
| `push.reconfirm-ignored` | RFC 8765 sec. 6.5 with verified erratum 8560: a server that does not implement RECONFIRM silently ignores it (M5 names it, no row carried it) | `[ ]` | `tests/test_push.py::test_unimplemented_reconfirm_is_ignored_silently` (to be written) | M5 |
| `discovery.registrar_from_zone()` | RFC 9665 sec. 3.1.1 (SRV at `_dnssd-srp._tcp.<zone>`, RFC 2782) | `[ ]` | `tests/test_discovery.py::test_registrar_from_zone` (to be written) | M3 |
| `dns.shared-codec` | The DNS message codec, the OPT/option layer, the name type, the SIG and KEY RDATA, `DnsOpCode.DSO` and `DSOTYPENI` are namespy's, a sibling path dependency (`pyproject.toml`: `pythonpath` and `mypy_path` `../namespy`), never a second copy. The lease option rides `namespy.edns.EdnsOption`, the DSO header is a namespy `DnsPacket` header, the UPDATE message is a `DnsPacket` | `[ok]` | `tests/test_lease.py::test_edns_option_roundtrip_through_the_shared_codec`, `tests/test_srp_message.py::test_dso_header_is_the_shared_codecs`, `tests/test_srp_message.py::test_update_message_round_trips_through_namespy`. A DSO session over namespy's stream framing is `session.transport` | M3 |
| `dns.namespy-gaps` | Closed 2026-11-13 in namespy: `DnsOpCode.DSO`, `DnsResponseCode.DSOTYPENI` (namespy listed 11 as unassigned; RFC 8490 sec. 10.2 assigns it), `RData_SIG` and `RData_KEY`. Nothing is worked around here | `[ok]` | `tests/test_srp_message.py::test_dso_header_is_the_shared_codecs`, `tests/test_sig0_rr.py::test_key_rr_has_zero_flags_and_protocol_three` | M2 |
| `dns.crypto-extra` | `cryptography` is used for the ECDSA P-256 signature primitive only (`dnssd-srp[crypto]`); every wire format, the SIG(0) construction and the lifetime check are ours | `[part]` | `tests/test_sig0.py::test_sign_without_the_backend_names_what_to_install`. Missing: a check that nothing else imports `cryptography` | M2 |

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
- RFC 9665 and RFC 8490 report no errata as of 2026-11-13 (rfclib). RFC 9664 reports none either.
- RFC 6763 is updated by RFC 8553; RFC 6762 has 2 errata on file, none verified.
- RFC 2136 has one verified erratum (4469, sec. 3.4.2.2, CNAME wording), and is updated by RFC 3007, 4033, 4034 and 4035.
- RFC 4034 (the KEY flags rule RFC 9665 sec. 3.3.3 paragraph 4 cites) has four verified errata and is updated by 4470, 6014, 6840, 6944, 9077, 9824 and 9905. RFC 6605 has none.
- **Stale reference inside RFC 9665 itself, not in this repository's docs.** RFC 9665 sec. 6.6 sends the reader to RFC 8624 sec. 3.1 for the SHOULD set of validation algorithms. rfclib: RFC 8624 is OBSOLETE, obsoleted by RFC 9904 (2025-11), which makes the IANA DNSSEC algorithm registries the canonical source (RFC 9904 sec. 1 paragraph 2). The `sig0.algorithm-set` row says what to read instead. (The 2026-11-12 research said this project's own files cite RFC 8624: a grep of every tracked file found no such citation.)
- RFC 2931 amends RFC 2535, which is OBSOLETE (RFC 4033, 4034, 4035 replaced it). RFC 2931 sec. 3 paragraph 1 keeps RFC 2535 sec. 4.1's SIG layout normative for SIG(0), so that section is cited for the layout and the obsolescence is stated beside it (`sig0.sig-rr`).
- RFC 8490 sec. 5.4.1 paragraph 2 corrects the research brief: whether a message is a request or a unidirectional one is "determined only by the specification for the Primary TLV", so the codec classifies by QR and MESSAGE ID only and the session applies the per-TLV rule (`session.primary-tlv-rules`).
- RFC 9665 sec. 5.1 paragraph 9: a response TTL above the *remaining* lease is "not an error". `registrar.ttl_for()` therefore caps the published TTL by the granted lease (sec. 4 paragraph 5's SHOULD NOT) and does not claim to check what is served.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| an mDNS responder: zeroconf owns the multicast link | `[no]` | a named document requires it |
| a recursive resolver, which is what namespy is | `[no]` | a named document requires it |
| a full DNS server: the registrar half is the update path, not a zone implementation | `[no]` | a named document requires it |

## 5. Open questions

- ~~share the DNS codec with namespy through a dependency, or keep a thin local layer~~ **Decided 2026-11-13** (the owner's fan-out instruction, 2026-11-13): namespy is a sibling path dependency and there is no second codec; see the `dns.` rows. Still open: namespy needs `DnsOpCode.DSO`, a SIG codec and a KEY codec (`dns.namespy-gaps`).
- how much of the registrar is a server rather than a validator
- M6 names a discovery proxy front end (RFC 8766), but no api row sits on it: add a proxy row, or drop the proxy from M6
  - Recommendation from the research, **not decided**: drop RFC 8766 from M6 for 0.1.0, because a discovery proxy bridges from mDNS and would need an mDNS reader, a declared non-goal above, and keep it as a non-goal to revisit. M6 still has no row.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] CI can resolve namespy: `.github/workflows/ci.yml` runs `pip install -e ".[dev]"`, which asks PyPI for `namespy` (not published) and finds nothing. Until it is published, the workflow must check out `b1tninja/namespy` beside this repository so the `../namespy` `pythonpath` and `mypy_path` resolve; at release those two entries go away. **Not done in this pass: workflow files were left alone.**
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
