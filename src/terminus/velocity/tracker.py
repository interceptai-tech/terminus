"""Bounded, thread-safe per-(agent, class) tumbling-window velocity counter."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from terminus.config.settings import get_settings


class VelocityTracker:
    """Per-(agent, class) tumbling-window counter with bounded memory.

    State is name-free: only ``(agent_id, class_key) -> (window_start, count)``.
    Memory is capped at ``max_tracked`` entries via LRU eviction, so an attacker
    rotating agent ids cannot exhaust memory. A single lock guards the
    read-modify-write so counts stay correct under concurrency. The caller wraps
    ``record_and_check`` so any error degrades to "no signal" (fail-open).
    """

    def __init__(
        self,
        window_seconds: int,
        threshold: int,
        max_tracked: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window = window_seconds
        self._threshold = threshold
        self._max = max_tracked
        self._clock = clock
        self._lock = threading.Lock()
        self._state: OrderedDict[tuple[str, str], tuple[float, int]] = OrderedDict()

    def record_and_check(self, agent_id: str, class_key: str) -> bool:
        """Record one event; return True iff it crosses the window threshold."""
        key = (agent_id, class_key)
        with self._lock:
            # now is read INSIDE the lock so each event is timestamped and
            # bucketed atomically: reading it before acquiring the lock would let
            # a thread stall between the clock read and the window read/update,
            # so a racing thread could reset the key into a new window first and
            # the stalled thread would then increment that new window with a
            # stale timestamp (misbucketing across the boundary).
            now = self._clock()
            entry = self._state.get(key)
            if entry is None or now - entry[0] > self._window:
                window_start, count = now, 1
            else:
                window_start, count = entry[0], entry[1] + 1
            self._state[key] = (window_start, count)
            self._state.move_to_end(key)  # mark most-recently-used
            while len(self._state) > self._max:
                self._state.popitem(last=False)  # evict least-recently-used
            return count > self._threshold


@dataclass(frozen=True)
class VelocityTrackers:
    """Separate bounded pools for authenticated vs unauthenticated traffic.

    Unauthenticated identities are self-asserted and unbounded in cardinality, so
    an attacker could otherwise flood observe-only buckets to LRU-evict (reset) an
    authenticated agent's enforcement counter. Isolating the pools means an unauth
    flood can only evict unauth buckets; the auth pool (keyed by JWT-verified
    subjects, naturally low-cardinality) is never evictable by untrusted traffic.
    """

    auth: VelocityTracker
    unauth: VelocityTracker


@lru_cache(maxsize=1)
def get_velocity_trackers() -> VelocityTrackers:
    """Process-wide singleton holder of the auth and unauth tracker pools."""
    s = get_settings()
    return VelocityTrackers(
        auth=VelocityTracker(
            s.velocity_window_seconds, s.velocity_threshold, s.velocity_max_tracked
        ),
        unauth=VelocityTracker(
            s.velocity_window_seconds, s.velocity_threshold, s.velocity_max_tracked
        ),
    )
