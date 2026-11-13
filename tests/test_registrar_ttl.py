"""TTL consistency and TTL policy (RFC 9665 section 4).

RFC 9665 gives no numbers for TTL bounds (they are the operator's, paragraph 5) and no vector,
so the policy tests state the rule they pin rather than a published value.
"""

from __future__ import annotations

import pytest

from dnssd_srp.model import UpdateRR, rrset_key
from dnssd_srp.registrar import RCODE_REFUSED, TtlPolicy, check_ttl_consistency, ttl_for

PTR = 12
SRV = 33
TXT = 16


def rr(name, rrtype, ttl):
    return UpdateRR(name, rrtype, ttl, b"")


def test_uniform_ttl_per_rrset_accepted():
    records = [rr("_srv._tcp.example.com.", PTR, 120), rr("_srv._tcp.example.com.", PTR, 120)]
    assert check_ttl_consistency(records) is True


def test_two_ptr_records_different_ttl_refused():
    records = [rr("_srv._tcp.example.com.", PTR, 120), rr("_srv._tcp.example.com.", PTR, 121)]
    assert check_ttl_consistency(records) is False
    assert RCODE_REFUSED == 5


def test_different_rrsets_may_have_different_ttls():
    records = [
        rr("_srv._tcp.example.com.", PTR, 120),
        rr("inst._srv._tcp.example.com.", SRV, 7200),
        rr("inst._srv._tcp.example.com.", TXT, 4500),
    ]
    assert check_ttl_consistency(records) is True


def test_rrset_key_is_name_and_type_case_insensitive():
    assert rrset_key(rr("Host.Local.", 1, 1)) == rrset_key(rr("host.local", 1, 9))
    assert check_ttl_consistency([rr("Host.Local.", 1, 100), rr("host.local.", 1, 101)]) is False
    # Same name, different type is a different RRset.
    assert check_ttl_consistency([rr("host.local.", 1, 100), rr("host.local.", 28, 101)]) is True


def test_non_ascii_octets_are_not_case_folded():
    # DNS folds ASCII only; the German capital sharp s must not become "ss" or lower-case.
    assert rrset_key(rr("STRASSE.", 1, 1)) != rrset_key(rr("STRAẞE.", 1, 1))


def test_empty_update_accepted_vacuously():
    assert check_ttl_consistency([]) is True


def test_one_inconsistent_rrset_among_many_refuses_the_whole_update():
    records = [rr(f"h{i}.example.", 1, 60) for i in range(50)]
    records.append(rr("h7.example.", 1, 61))
    assert check_ttl_consistency(records) is False


def test_ttl_never_exceeds_lease():
    policy = TtlPolicy(minimum=10, maximum=86400)
    assert ttl_for(3600, 600, policy) == 600
    assert ttl_for(30, 600, policy) == 30


def test_ttl_clamped_to_policy_bounds():
    policy = TtlPolicy(minimum=120, maximum=3600)
    assert ttl_for(5, 10**6, policy) == 120
    assert ttl_for(10**6, 10**7, policy) == 3600
    assert ttl_for(900, 10**6, policy) == 900


def test_lease_shorter_than_minimum_wins():
    # Both are SHOULDs in section 4 paragraph 5; the lease is the one that must not be outlived.
    assert ttl_for(5, 60, TtlPolicy(minimum=120, maximum=3600)) == 60
    assert ttl_for(5, 0, TtlPolicy(minimum=120, maximum=3600)) == 0


def test_policy_with_minimum_above_maximum_refused():
    with pytest.raises(ValueError, match="minimum <= maximum"):
        TtlPolicy(minimum=10, maximum=5)
    with pytest.raises(ValueError, match="minimum <= maximum"):
        TtlPolicy(minimum=-1, maximum=5)


@pytest.mark.parametrize("bad", [-1, 2**32])
def test_negative_or_oversized_ttl_refused(bad):
    policy = TtlPolicy(minimum=0, maximum=100)
    with pytest.raises(ValueError, match="requested TTL"):
        ttl_for(bad, 10, policy)
    with pytest.raises(ValueError, match="lease"):
        ttl_for(10, bad, policy)
    with pytest.raises(ValueError, match="TTL"):
        rr("a.example.", 1, bad)


def test_no_default_policy_exists():
    with pytest.raises(TypeError):
        TtlPolicy()
