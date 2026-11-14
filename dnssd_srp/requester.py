"""The SRP requester's timing and sequencing rules, sans-IO (RFC 9664 sec. 4.2 and 5.2, RFC 9665).

Nothing here sends a datagram or reads a clock: every method takes ``now`` in seconds from the
caller's clock and returns when the caller should next act, and the random choices come from an
injected generator, so a test can run a day of refreshes in microseconds.

What is pinned, each by ``tests/test_requester.py``:

* the initial Registration Request is delayed by a random 0 to 3000 ms at a granularity of 10 ms
  (RFC 9664 section 4.2 paragraph 4);
* one update in flight at a time, and a change that arrives meanwhile is held until the response
  (RFC 9665 section 3.2.3.3 paragraph 1);
* the lease in the response replaces the requested one, shorter or longer, and a response with no
  Update Lease option is read as if the server had echoed the request (RFC 9664 section 4.2
  paragraphs 2 and 3, RFC 9665 section 5.1 paragraph 6);
* the refresh time is 80% of the lease plus a random 0% to 5% of it, counted from when the update
  was first transmitted (RFC 9664 section 5.2 paragraph 2, RFC 9665 section 5.1 paragraph 7);
* retries of a refresh that got no response, spaced evenly up to the expiry (RFC 9664 section 5.2
  paragraph 5, whose nine retries are an example, not a requirement).
* retransmission of an update that went out as a UDP datagram and was not answered (RFC 9664
  section 6, RFC 9665 section 3.2.3.2): the same message again after a wait that doubles to a cap,
  a bounded number of times, then :meth:`Requester.give_up`. RFC 9664 section 6 gives no numbers
  and sends the reader to RFC 1035 section 4.2.1 (a minimum retransmission interval of 2 to 5
  seconds), RFC 1536 section 1 (back off exponentially, probably to a maximum) and RFC 8085
  section 3.1.3 (1 second RECOMMENDED as an initial value, shorter values likely problematic).
  :class:`RetransmitPolicy` holds the choice made here: 2 seconds, doubling, capped at 30 seconds,
  four transmissions in all. The lease clock still runs from the first transmission. Over a
  stream there is no retransmission at this layer.

Not here: the socket, coalescing of Refresh Requests (section 5.2.1, a MAY) and the choice of the lease to ask for.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .lease import UpdateLease

__all__ = [
    "REFRESH_FRACTION",
    "REFRESH_JITTER_FRACTION",
    "REGISTRATION_DELAY_GRANULARITY_MS",
    "REGISTRATION_DELAY_MAX_MS",
    "RETRANSMIT_MIN_INITIAL",
    "RandomSource",
    "Requester",
    "RequesterError",
    "RequesterState",
    "RetransmitPolicy",
    "refresh_retry_times",
    "registration_delay",
]

REGISTRATION_DELAY_MAX_MS = 3000  # RFC 9664 section 4.2 paragraph 4: "0-3000 milliseconds"
REGISTRATION_DELAY_GRANULARITY_MS = 10  # "a granularity of no more than 10 milliseconds"
REFRESH_FRACTION = 0.80  # RFC 9664 section 5.2 paragraph 2: "80% of the lease duration"
REFRESH_JITTER_FRACTION = 0.05  # "plus a random offset between 0% and 5% of the lease duration"
RETRANSMIT_MIN_INITIAL = (
    0.5  # RFC 8085 section 3.1.3: 500 ms is used by others, shorter "problematic"
)


class RandomSource(Protocol):
    """The two methods of :class:`random.Random` this module uses."""

    def randrange(self, start: int, stop: int, /) -> int: ...

    def uniform(self, a: float, b: float, /) -> float: ...


class RequesterError(RuntimeError):
    """A call that the requester's rules forbid in its present state."""


class RequesterState(Enum):
    """Where the requester is in the life of one registration."""

    IDLE = "idle"  # nothing registered, nothing in flight
    DELAYED = "delayed"  # the first Registration Request is waiting out its random delay
    IN_FLIGHT = "in-flight"  # one update sent, no response yet
    REGISTERED = "registered"  # a response arrived; waiting for the refresh time
    FAILED = "failed"  # a datagram update went unanswered through every retransmission


@dataclass(frozen=True)
class RetransmitPolicy:
    """How an unanswered UDP update is retransmitted (see the module text for the sources).

    ``initial`` seconds after the first transmission, then ``factor`` times longer after each
    retransmission, never more than ``cap``; ``transmissions`` counts the first send, so 4 means
    three retransmissions. After the last transmission the same wait applies once more before the
    update is given up. These numbers are this library's choice: RFC 9664 section 6 names none.
    """

    initial: float = 2.0
    factor: float = 2.0
    cap: float = 30.0
    transmissions: int = 4

    def __post_init__(self) -> None:
        if self.initial < RETRANSMIT_MIN_INITIAL:
            raise ValueError(
                f"an initial wait under {RETRANSMIT_MIN_INITIAL} s is the fast retry of RFC 1536"
            )
        if self.factor < 1.0 or self.cap < self.initial or self.transmissions < 1:
            raise ValueError("the policy must back off, not shrink, and send at least once")

    def waits(self) -> tuple[float, ...]:
        """The wait after each transmission: the last one ends in giving up."""
        out: list[float] = []
        wait = self.initial
        for _ in range(self.transmissions):
            out.append(min(wait, self.cap))
            wait *= self.factor
        return tuple(out)


def registration_delay(rng: RandomSource) -> float:
    """The delay before the first Registration Request, in seconds (RFC 9664 section 4.2 para 4).

    A whole number of 10 ms steps from 0 ms to 3000 ms inclusive, so the granularity is exactly
    the 10 ms the RFC allows and both ends of the range are reachable.
    """
    steps = REGISTRATION_DELAY_MAX_MS // REGISTRATION_DELAY_GRANULARITY_MS
    return rng.randrange(0, steps + 1) * REGISTRATION_DELAY_GRANULARITY_MS / 1000.0


def refresh_retry_times(first_failure: float, expiry: float, retries: int = 9) -> list[float]:
    """Times for the retries of an unanswered Refresh Request (RFC 9664 section 5.2 paragraph 5).

    "the Requester could retry nine more times, spaced uniformly at equal intervals from the time
    of the first failed Refresh attempt until the expiration time of the records." The last retry
    lands on the expiry itself. The RFC calls this an example, so ``retries`` is a parameter.
    """
    if retries < 1:
        raise ValueError("at least one retry is needed")
    if expiry <= first_failure:
        raise ValueError("the expiry must come after the first failed attempt")
    step = (expiry - first_failure) / retries
    return [first_failure + step * n for n in range(1, retries + 1)]


@dataclass(frozen=True)
class _Outstanding:
    sent_at: float
    requested: UpdateLease
    waits: tuple[float, ...] = ()  # empty: a stream, nothing to retransmit here
    transmissions: int = 1
    next_at: float | None = None


class Requester:
    """One SRP registration's schedule: when to send, what the response changed, when to refresh."""

    def __init__(self, rng: RandomSource) -> None:
        self._rng = rng
        self._state = RequesterState.IDLE
        self._outstanding: _Outstanding | None = None
        self._granted: UpdateLease | None = None
        self._refresh_at: float | None = None
        self._expires_at: float | None = None
        self._change_pending = False
        self._first_send_at: float | None = None

    @property
    def state(self) -> RequesterState:
        return self._state

    @property
    def granted(self) -> UpdateLease | None:
        """The lease in force: the response's, or the request's when the response had none."""
        return self._granted

    @property
    def refresh_at(self) -> float | None:
        """When the next Refresh Request is due, or None before the first response."""
        return self._refresh_at

    @property
    def expires_at(self) -> float | None:
        """When the registered records lapse, counted from the update's first transmission."""
        return self._expires_at

    @property
    def change_pending(self) -> bool:
        """True when a configuration change arrived while an update was in flight."""
        return self._change_pending

    def start(self, now: float) -> float:
        """Begin the first registration: the time at which the first update may be sent.

        RFC 9664 section 4.2 paragraph 4 applies "only to the initial Registration Request on
        startup", so this is called once; a second call is an error.
        """
        if self._state is not RequesterState.IDLE or self._first_send_at is not None:
            raise RequesterError("the initial Registration Request was already scheduled")
        self._first_send_at = now + registration_delay(self._rng)
        self._state = RequesterState.DELAYED
        return self._first_send_at

    def send(
        self,
        now: float,
        lease: UpdateLease,
        *,
        datagram: bool = False,
        policy: RetransmitPolicy | None = None,
    ) -> None:
        """Record that an update carrying ``lease`` went out at ``now``.

        ``datagram`` says it went over UDP, which arms retransmission under ``policy`` (the
        default :class:`RetransmitPolicy`); an update over a stream is never retransmitted here.

        RFC 9665 section 3.2.3.3 paragraph 1: until an earlier update "has been acknowledged, the
        requester MUST NOT send any subsequent SRP Updates", so a send while one is in flight
        raises. The first update may not leave before the delay :meth:`start` returned.
        """
        if self._outstanding is not None:
            raise RequesterError("an SRP Update is in flight; the next waits for its response")
        if self._state is RequesterState.DELAYED:
            if self._first_send_at is None or now < self._first_send_at:
                raise RequesterError("the initial Registration Request is still inside its delay")
        elif self._state is RequesterState.IDLE:
            raise RequesterError("start() has not scheduled the initial Registration Request")
        waits = (policy or RetransmitPolicy()).waits() if datagram else ()
        self._outstanding = _Outstanding(now, lease, waits, 1, now + waits[0] if waits else None)
        self._state = RequesterState.IN_FLIGHT

    @property
    def next_retransmit_at(self) -> float | None:
        """When to act on the update in flight: send it again, or give it up. None for none."""
        return None if self._outstanding is None else self._outstanding.next_at

    def retransmit_due(self, now: float) -> str | None:
        """``"retransmit"`` or ``"give-up"`` when the wait for a response has run out at ``now``.

        The last transmission's wait ends in ``"give-up"``; every earlier one in ``"retransmit"``.
        """
        sent = self._outstanding
        if sent is None or sent.next_at is None or now < sent.next_at:
            return None
        return "give-up" if sent.transmissions >= len(sent.waits) else "retransmit"

    def note_retransmission(self, now: float) -> float:
        """Record that the same update went out again at ``now``; the time to act next.

        The message is the same, with the same message ID (RFC 1536 section 1 condition c is what
        marks a retry, and what a server uses to drop the duplicate), and the lease still counts
        from the first transmission.
        """
        sent = self._outstanding
        if sent is None or self.retransmit_due(now) != "retransmit":
            raise RequesterError("no retransmission is due")
        self._outstanding = _Outstanding(
            sent.sent_at,
            sent.requested,
            sent.waits,
            sent.transmissions + 1,
            now + sent.waits[sent.transmissions],
        )
        return self._outstanding.next_at or now

    def give_up(self, now: float) -> None:
        """Abandon the update in flight after :meth:`retransmit_due` said ``"give-up"``.

        The requester is FAILED: nothing is registered by this attempt, and a later :meth:`send`
        (to another registrar, or the same one later) starts a fresh attempt with no initial delay.
        """
        if self.retransmit_due(now) != "give-up":
            raise RequesterError("the update in flight has not used up its retransmissions")
        self._outstanding = None
        self._state = RequesterState.FAILED

    def note_change(self) -> bool:
        """A configuration change. True when it can go out now, False when it must wait.

        RFC 9665 section 3.2.3.3 paragraph 1 asks for the change to be deferred until the update
        in flight "has completed"; :meth:`on_response` then reports it.
        """
        if self._outstanding is not None:
            self._change_pending = True
            return False
        return True

    def on_response(self, now: float, granted: UpdateLease | None) -> bool:
        """Take the response to the update in flight. True when a deferred change is now due.

        ``granted`` is the Update Lease option from the response, or None when it carried none:
        then the requester continues "as if the server had returned an identical Update Lease
        option" (RFC 9664 section 4.2 paragraph 2). When there is one, its durations replace the
        requested ones whether shorter or longer (paragraph 3, RFC 9665 section 5.1 paragraph 6).
        The refresh time is 80% of the lease plus 0% to 5% of it, from the first transmission
        (RFC 9664 section 5.2 paragraph 2, RFC 9665 section 5.1 paragraph 7).
        """
        if self._outstanding is None:
            raise RequesterError("a response arrived with no update in flight")
        sent = self._outstanding
        self._outstanding = None
        lease = sent.requested if granted is None else granted
        self._granted = lease
        seconds = float(lease.lease)
        jitter = self._rng.uniform(0.0, REFRESH_JITTER_FRACTION) * seconds
        self._refresh_at = sent.sent_at + REFRESH_FRACTION * seconds + jitter
        self._expires_at = sent.sent_at + seconds
        self._state = RequesterState.REGISTERED
        due = self._change_pending
        self._change_pending = False
        # A response after the refresh time has gone by cannot schedule into the past.
        if self._refresh_at < now:
            self._refresh_at = now
        return due

    def on_refresh_due(self, now: float) -> bool:
        """True when a Refresh Request should be sent at ``now`` (RFC 9664 section 5.2 para 2)."""
        return (
            self._state is RequesterState.REGISTERED
            and self._refresh_at is not None
            and now >= self._refresh_at
        )
