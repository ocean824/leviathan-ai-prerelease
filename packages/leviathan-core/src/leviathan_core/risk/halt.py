"""The single named-halt authority for risk, API and isolated replay."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime

from leviathan_core.risk.halt_store import (
    FAULT_REASON,
    HaltStore,
    HaltStoreError,
    normalize_reason,
    timestamp_utc,
)


@dataclass
class MutationResponseState:
    commit_status: str = "NOT_COMMITTED"


_mutation_response: ContextVar[MutationResponseState | None] = ContextVar(
    "halt_mutation_response", default=None
)


@contextmanager
def mutation_response_scope() -> Iterator[MutationResponseState]:
    """Share commit certainty with a single HTTP request, including its worker thread."""
    state = MutationResponseState()
    token = _mutation_response.set(state)
    try:
        yield state
    finally:
        _mutation_response.reset(token)


def _set_commit_status(status: str) -> None:
    response = _mutation_response.get()
    if response is not None:
        response.commit_status = status


class HaltAuthority:
    """Volatile by default; a supplied HaltStore is the durable authority.

    The same reentrant lock covers mutations, safety reads and the final
    synchronous route-to-paper consumption seam.
    """

    def __init__(
        self,
        store: HaltStore | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._mutex = threading.RLock()
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._halts: dict[str, str] = store.load(integrity=True) if store is not None else {}
        self._fault = False
        self._generation = 0
        self._engage_fence: Callable[[], AbstractContextManager[bool]] | None = None

    def bind_engage_fence(self, fence: Callable[[], AbstractContextManager[bool]]) -> None:
        """Install the process-wide pre-commit dispatch fence exactly once."""
        if not callable(fence):
            raise TypeError("HALT_ENGAGE_FENCE_REQUIRED")
        with self._mutex:
            if self._engage_fence is not None and self._engage_fence is not fence:
                raise RuntimeError("HALT_ENGAGE_FENCE_ALREADY_BOUND")
            self._engage_fence = fence

    @property
    def generation(self) -> int:
        """Monotonic durable generation when backed by HaltStore."""
        with self._mutex:
            self._refresh()
            if self._fault:
                raise HaltStoreError(commit_status="NOT_COMMITTED")
            if self._store is not None:
                try:
                    self._generation = max(self._generation, self._store.generation)
                except HaltStoreError:
                    self._fault = True
                    raise
            return self._generation

    def _refresh(self) -> None:
        if self._store is not None and not self._fault:
            try:
                self._halts = self._store.load()
            except HaltStoreError:
                self._fault = True

    @property
    def fault_code(self) -> str | None:
        with self._mutex:
            self._refresh()
            return "HALT_STORE_UNAVAILABLE" if self._fault else None

    def engage(self, reason: str) -> None:
        reason = normalize_reason(reason)
        _set_commit_status("NOT_COMMITTED")
        fence = self._engage_fence
        # The injected hook is outside _mutex to keep the lock order consistent
        # with the final dispatch seam (dispatch fence, then HALT mutex). A
        # timed-out hook still yields and allows the safety commit to proceed.
        with fence() if fence is not None else nullcontext(True), self._mutex:
            self._refresh()
            if self._fault:
                raise HaltStoreError(commit_status="NOT_COMMITTED")
            if reason in self._halts:
                return
            at = timestamp_utc(self._clock())
            if self._store is not None:
                try:
                    changed, current = self._store.mutate(reason, engage_at=at)
                except HaltStoreError as exc:
                    self._fault = True
                    _set_commit_status(exc.commit_status)
                    raise
                self._halts = current
                if changed:
                    self._generation += 1
                    _set_commit_status("COMMITTED")
            else:
                self._halts[reason] = at
                self._generation += 1

    def lift(self, reason: str) -> None:
        self.lift_committed(reason)

    def lift_committed(self, reason: str) -> bool:
        reason = normalize_reason(reason)
        _set_commit_status("NOT_COMMITTED")
        with self._mutex:
            self._refresh()
            if self._fault:
                raise HaltStoreError(commit_status="NOT_COMMITTED")
            if reason not in self._halts:
                return False
            if self._store is not None:
                try:
                    changed, current = self._store.mutate(reason, engage_at=None)
                except HaltStoreError as exc:
                    self._fault = True
                    _set_commit_status(exc.commit_status)
                    raise
                self._halts = current
                if changed:
                    _set_commit_status("COMMITTED")
                    self._generation += 1
                return changed
            del self._halts[reason]
            self._generation += 1
            return True

    @property
    def halted(self) -> bool:
        with self._mutex:
            self._refresh()
            return self._fault or bool(self._halts)

    @property
    def active(self) -> tuple[str, ...]:
        with self._mutex:
            self._refresh()
            return tuple(sorted((*self._halts, *((FAULT_REASON,) if self._fault else ()))))

    def snapshot(self) -> dict[str, str]:
        with self._mutex:
            self._refresh()
            return dict(self._halts)

    @contextmanager
    def route_interlock(self) -> Iterator[None]:
        """No await or product SQL operation belongs inside this scope."""
        with self._mutex:
            self._refresh()
            yield

    def close(self) -> None:
        with self._mutex:
            if self._store is not None:
                self._store.close()
                self._store = None
            self._fault = True
