"""Retransmission of an unanswered SRP update (RFC 9664 section 6) and the Fast Open refusal
(RFC 9665 section 6.1).

RFC 9664 section 6 gives no numbers, so the schedule tests pin this library's documented choice
(2 s doubling to 30 s, four transmissions) and the properties the cited guidance asks for: no
fast retry, exponential back-off, a cap, a bound, the lease clock from the first transmission.
"""

from __future__ import annotations

import socket

import pytest

from dnssd_srp.fastopen import FastOpenState, accept_fast_open_payload, refuse_fast_open
from dnssd_srp.lease import UpdateLease
from dnssd_srp.requester import Requester, RequesterError, RequesterState, RetransmitPolicy


class Fixed:
    def randrange(self, start: int, stop: int, /) -> int:
        return start

    def uniform(self, a: float, b: float, /) -> float:
        return a


def lease(seconds: int = 7200) -> UpdateLease:
    return UpdateLease(seconds)


def started() -> Requester:
    requester = Requester(Fixed())
    requester.start(0.0)
    return requester


def test_the_default_waits_are_two_seconds_doubling_and_capped() -> None:
    assert RetransmitPolicy().waits() == (2.0, 4.0, 8.0, 16.0)
    assert RetransmitPolicy(initial=2.0, cap=10.0, transmissions=5).waits() == (
        2.0,
        4.0,
        8.0,
        10.0,
        10.0,
    )


@pytest.mark.parametrize(
    "kwargs",
    [{"initial": 0.1}, {"factor": 0.5}, {"cap": 1.0}, {"transmissions": 0}],
)
def test_a_policy_that_would_hammer_the_registrar_or_never_send_is_refused(kwargs) -> None:
    with pytest.raises(ValueError, match=r"fast retry|back off"):
        RetransmitPolicy(**kwargs)


def test_an_unanswered_datagram_is_retransmitted_on_the_schedule_then_given_up() -> None:
    requester = started()
    requester.send(0.0, lease(), datagram=True)
    assert requester.next_retransmit_at == 2.0
    assert requester.retransmit_due(1.99) is None
    assert requester.retransmit_due(2.0) == "retransmit"
    assert requester.note_retransmission(2.0) == 6.0  # 2 s after the first, then 4 s
    assert requester.note_retransmission(6.0) == 14.0
    assert requester.note_retransmission(14.0) == 30.0  # the last transmission waits 16 s
    assert requester.retransmit_due(29.9) is None
    assert requester.retransmit_due(30.0) == "give-up"
    requester.give_up(30.0)
    assert requester.state is RequesterState.FAILED
    assert requester.next_retransmit_at is None


def test_a_response_between_retransmissions_ends_the_retries_and_the_lease_counts_from_the_first_send() -> (
    None
):
    requester = started()
    requester.send(0.0, lease(1000), datagram=True)
    requester.note_retransmission(2.0)
    requester.on_response(3.0, None)
    assert requester.next_retransmit_at is None
    assert requester.retransmit_due(100.0) is None
    assert requester.expires_at == 1000.0  # from 0.0, not from the retransmission at 2.0


def test_a_stream_update_is_never_retransmitted() -> None:
    requester = started()
    requester.send(0.0, lease())
    assert requester.next_retransmit_at is None
    assert requester.retransmit_due(10_000.0) is None


def test_retransmission_calls_out_of_turn_are_refused() -> None:
    requester = started()
    requester.send(0.0, lease(), datagram=True)
    with pytest.raises(RequesterError):
        requester.note_retransmission(1.0)  # not due yet
    with pytest.raises(RequesterError):
        requester.give_up(2.0)  # retransmissions remain
    for at in (2.0, 6.0, 14.0):
        requester.note_retransmission(at)
    with pytest.raises(RequesterError):
        requester.note_retransmission(30.0)  # nothing left to retransmit, only to give up


def test_while_an_update_is_unanswered_the_next_one_still_waits() -> None:
    requester = started()
    requester.send(0.0, lease(), datagram=True)
    requester.note_retransmission(2.0)
    with pytest.raises(RequesterError):
        requester.send(3.0, lease(), datagram=True)  # RFC 9665 section 3.2.3.3: one in flight


def test_after_giving_up_a_fresh_attempt_needs_no_initial_delay() -> None:
    requester = started()
    requester.send(0.0, lease(), datagram=True)
    for at in (2.0, 6.0, 14.0):
        requester.note_retransmission(at)
    requester.give_up(30.0)
    requester.send(31.0, lease(), datagram=True)
    assert requester.state is RequesterState.IN_FLIGHT
    assert requester.next_retransmit_at == 33.0


def test_a_custom_policy_governs_the_schedule() -> None:
    requester = started()
    requester.send(
        0.0, lease(), datagram=True, policy=RetransmitPolicy(initial=1.0, transmissions=2)
    )
    assert requester.next_retransmit_at == 1.0
    assert requester.note_retransmission(1.0) == 3.0
    assert requester.retransmit_due(3.0) == "give-up"


# ------------------------------------------------------------------ TCP Fast Open


def test_the_default_is_the_must_not_and_only_an_operator_statement_lifts_it() -> None:
    assert accept_fast_open_payload() is False
    assert accept_fast_open_payload(path_validated=False) is False
    assert accept_fast_open_payload(path_validated=True) is True


@pytest.mark.skipif(
    not hasattr(socket, "TCP_FASTOPEN"), reason="this platform has no TCP_FASTOPEN socket option"
)
def test_a_listener_that_asked_for_fast_open_is_made_to_refuse_it() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)  # the negative control
        assert listener.getsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN) != 0
        assert refuse_fast_open(listener) is FastOpenState.DISABLED
        assert listener.getsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN) == 0


def test_a_platform_without_the_option_is_reported_not_assumed_safe(monkeypatch) -> None:
    monkeypatch.delattr(socket, "TCP_FASTOPEN", raising=False)
    with socket.socket() as listener:
        assert refuse_fast_open(listener) is FastOpenState.UNAVAILABLE
