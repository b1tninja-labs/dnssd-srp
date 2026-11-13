# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9665 | Proposed Standard | 2025-06 | 2026-11-05 |
| RFC 8765 | Proposed Standard | 2020-06 | 2026-11-05 |
| RFC 8490 | Proposed Standard | 2019-03 | 2026-11-05 |
| RFC 8766 | Proposed Standard | 2020-06 | 2026-11-05 |
| RFC 2931 | Proposed Standard | 2000-09 | 2026-11-05 |
| RFC 6763 | Proposed Standard | 2013-02 | 2026-11-05 |
| RFC 6762 | Proposed Standard | 2013-02 | 2026-11-05 |
| RFC 9664 | Proposed Standard | 2025-06 | 2026-11-13 |
| RFC 2136 | Proposed Standard | 1997-04 | 2026-11-13 |
| RFC 4034 | Proposed Standard | 2005-03 | 2026-11-13 |
| RFC 6605 | Proposed Standard | 2012-04 | 2026-11-13 |
| RFC 6891 | Internet Standard (STD 75) | 2013-04 | 2026-11-13 |
| RFC 2782 | Proposed Standard | 2000-02 | 2026-11-13 |
| RFC 7858 | Proposed Standard | 2016-05 | 2026-11-13 |
| RFC 9904 | Proposed Standard | 2025-11 | 2026-11-13 |
| RFC 8624 | **Obsolete** (obsoleted by RFC 9904) | 2019-06 | 2026-11-13 |
| RFC 2535 | **Obsolete** (obsoleted by RFC 4033, 4034, 4035) | 1999-03 | 2026-11-13 |

Notes on the rows added 2026-11-13 (all read through the RFC library the same day):

- **RFC 9664** is mandatory for SRP: RFC 9665 sec. 3.3.2 paragraph 2 and sec. 5.1 paragraphs 1, 6 and 8 require the Update Lease option in every SRP Update and Response. It has no errata. `dnssd_srp/lease.py` is its codec.
- **RFC 2136** is the DNS Update an SRP Update is. One verified erratum (4469, sec. 3.4.2.2, CNAME wording), not touched by any row here. Updated by RFC 3007 and 4033-4035.
- **RFC 4034** supplies the KEY flags rule that RFC 9665 sec. 3.3.3 paragraph 4 cites. Four verified errata; updated by 4470, 6014, 6840, 6944, 9077, 9824 and 9905.
- **RFC 6605** gives algorithm 13 its key (`x | y`) and signature (`r | s`, 32 octets each) layout in sec. 4, and the P-256 vector of sec. 6.1 used by `tests/test_sig0.py`. No errata.
- **RFC 6891** is the OPT RR the Update Lease option rides in (RFC 9664 sec. 4 paragraph 1). One verified erratum, not used here.
- **RFC 2782** names the SRV record the registrar is found by (RFC 9665 sec. 3.1.1). One verified erratum; read it before `discovery.registrar_from_zone()`. Updated by RFC 6335 and 8553.
- **RFC 7858** is the TLS leg RFC 9665 sec. 7 requires of a registrar (not re-read here). Updated by RFC 8310; one unverified erratum.
- **RFC 9904 obsoletes RFC 8624.** RFC 9665 sec. 6.6 still points at RFC 8624 sec. 3.1 for the SHOULD set of validation algorithms; RFC 9904 sec. 1 paragraph 2 moved the canonical table to the IANA DNSSEC algorithm registries. Read the registry, not RFC 8624. RFC 8624 is listed so that nobody cites it as live.
- **RFC 2535** is obsolete, yet RFC 2931 sec. 3 paragraph 1 keeps its SIG layout (sec. 4.1) normative for SIG(0). Cite it for that layout only, and say it is obsolete.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
