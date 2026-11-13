"""The requester's timing and sequencing rules (RFC 9664 sec. 4.2 and 5.2, RFC 9665 sec. 3.2.3.3).

The RFCs print no timeline, so each expectation is the arithmetic of the paragraph it names, run
against a seeded generator and against fixed stand-ins that pin both ends of each random range.
"""

from __future__ import annotations

import random
from itertools import pairwise

import pytest

from dnssd_srp.lease import UpdateLease
from dnssd_srp.requester import (
    Requester,
    RequesterError,
    RequesterState,
    refresh_retry_times,
    registration_delay,
)


class Fixed:
    """A generator that always answers with the low or the high end of the range asked."""

    def __init__(self, high: bool) -> None:
        self.high = high

    def randrange(self, start: int, stop: int, /) -> int:
        return stop - 1 if self.high else start

    def uniform(self, a: float, b: float, /) -> float:
        return b if self.high else a


def test_initial_registration_delay_is_0_to_3000_ms_in_10_ms_steps() -> None:
    assert registration_delay(Fixed(False)) == 0.0
    assert registration_delay(Fixed(True)) == 3.0  # both ends of 0-3000 ms are reachable
    seen = {round(registration_delay(random.Random(n)) * 1000) for n in range(400)}
    assert all(0 <= ms <= 3000 and ms % 10 == 0 for ms in seen)
    assert len(seen) > 100  # a spread, not one value
    assert max(seen) > 2500
    assert min(seen) < 500


def test_the_first_update_cannot_leave_inside_its_delay() -> None:
    requester = Requester(Fixed(True))
    assert requester.start(100.0) == 103.0
    assert requester.state is RequesterState.DELAYED
    with pytest.raises(RequesterError):
        requester.send(102.99, UpdateLease(7200))
    requester.send(103.0, UpdateLease(7200))
    assert requester.state is RequesterState.IN_FLIGHT


def test_the_delay_applies_once_and_only_to_the_initial_request() -> None:
    requester = Requester(Fixed(False))
    with pytest.raises(RequesterError):
        requester.send(0.0, UpdateLease(60))  # start() never ran
    requester.start(0.0)
    with pytest.raises(RequesterError):
        requester.start(1.0)
    requester.send(0.0, UpdateLease(100))
    requester.on_response(0.1, None)
    requester.send(80.0, UpdateLease(100))  # a refresh needs no start-up delay
    assert requester.state is RequesterState.IN_FLIGHT


def test_one_update_in_flight_and_a_change_waits_for_its_response() -> None:
    requester = Requester(Fixed(False))
    requester.start(0.0)
    assert requester.note_change() is True  # nothing in flight: it can go now
    requester.send(0.0, UpdateLease(1800))
    with pytest.raises(RequesterError):
        requester.send(0.5, UpdateLease(1800))  # RFC 9665 section 3.2.3.3 paragraph 1
    assert requester.note_change() is False
    assert requester.change_pending
    assert requester.on_response(1.0, None) is True  # the deferred change is now due
    assert not requester.change_pending
    requester.send(1.0, UpdateLease(1800))
    assert requester.on_response(2.0, None) is False


def test_a_response_with_no_lease_is_read_as_the_request_echoed() -> None:
    requester = Requester(Fixed(False))
    requester.start(0.0)
    requester.send(0.0, UpdateLease(1800, 86400))
    requester.on_response(0.2, None)
    assert requester.granted == UpdateLease(1800, 86400)
    assert requester.refresh_at == pytest.approx(0.8 * 1800)
    assert requester.expires_at == pytest.approx(1800)


@pytest.mark.parametrize("granted", [600, 7200])
def test_requester_renews_on_the_granted_lease(granted: int) -> None:
    """RFC 9664 section 4.2 paragraph 3: the response's duration rules, shorter or longer."""
    requester = Requester(Fixed(False))
    requester.start(10.0)
    requester.send(10.0, UpdateLease(1800))
    requester.on_response(10.3, UpdateLease(granted, 14 * 86400))
    assert requester.granted == UpdateLease(granted, 14 * 86400)
    assert requester.refresh_at == pytest.approx(10.0 + 0.8 * granted)
    assert requester.expires_at == pytest.approx(10.0 + granted)
    assert not requester.on_refresh_due(10.0 + 0.8 * granted - 0.01)
    assert requester.on_refresh_due(10.0 + 0.8 * granted)


def test_the_refresh_time_adds_zero_to_five_percent_of_the_lease() -> None:
    low, high = Requester(Fixed(False)), Requester(Fixed(True))
    for requester in (low, high):
        first = requester.start(0.0)
        requester.send(first, UpdateLease(1000))
        requester.on_response(first + 1.0, None)
    assert low.refresh_at == pytest.approx(800.0)
    assert high.refresh_at == pytest.approx(853.0)  # sent at 3.0 s, then 80% + 5% of 1000
    assert high.refresh_at is not None
    assert high.expires_at is not None
    assert high.refresh_at < high.expires_at  # a refresh always precedes the expiry
    spread = set()
    for seed in range(50):
        r = Requester(random.Random(seed))
        first = r.start(0.0)
        r.send(first, UpdateLease(1000))
        r.on_response(first + 0.1, None)
        assert r.refresh_at is not None
        offset = r.refresh_at - first - 800.0
        assert 0.0 <= offset <= 50.0
        spread.add(round(offset, 3))
    assert len(spread) > 20


def test_the_lease_runs_from_the_first_transmission_not_the_response() -> None:
    """RFC 9665 section 5.1 paragraph 7: a late response must not stretch the requester's lease."""
    requester = Requester(Fixed(False))
    requester.start(0.0)
    requester.send(0.0, UpdateLease(100))
    requester.on_response(5.0, UpdateLease(100))
    assert requester.expires_at == pytest.approx(100.0)  # not 105


def test_a_response_with_nothing_in_flight_is_refused() -> None:
    with pytest.raises(RequesterError):
        Requester(Fixed(False)).on_response(0.0, None)


def test_refresh_retries_are_evenly_spaced_up_to_the_expiry() -> None:
    times = refresh_retry_times(800.0, 1000.0)
    assert len(times) == 9  # the RFC's example of nine more tries
    assert times[-1] == pytest.approx(1000.0)
    gaps = {round(b - a, 9) for a, b in pairwise(times)}
    assert gaps == {round(200.0 / 9, 9)}
    assert len(refresh_retry_times(0.0, 10.0, retries=4)) == 4
    with pytest.raises(ValueError, match="after the first"):
        refresh_retry_times(10.0, 10.0)
    with pytest.raises(ValueError, match="one retry"):
        refresh_retry_times(0.0, 10.0, retries=0)
