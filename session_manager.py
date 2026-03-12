"""Session manager for emulation engine instances."""

import os
import threading
import time
import uuid
from typing import Any

from engines.base import BaseEngine


class SessionManager:
    """Manages emulation engine sessions with auto-cleanup."""

    SESSION_TIMEOUT_S = int(os.getenv("EMU_SESSION_TIMEOUT", "1800"))

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._last_cleanup: float = 0.0   # epoch seconds; 0 forces first cleanup immediately

    def create_session(self, engine: BaseEngine, label: str = "") -> str:
        """Register a new engine instance. Returns session_id."""
        session_id = f"emu-{uuid.uuid4().hex[:8]}"
        with self._lock:
            self._sessions[session_id] = {
                "engine": engine,
                "created_at": time.time(),
                "label": label,
            }
        return session_id

    def get(self, session_id: str) -> BaseEngine:
        """Get engine by session_id. Raises KeyError if not found or expired."""
        self._cleanup_expired()
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                raise KeyError(f"Session '{session_id}' not found. Use emu_list_sessions to see active sessions.")
            entry["engine"]._touch()
            return entry["engine"]

    def close(self, session_id: str) -> bool:
        """Close and clean up a session. Returns True if found."""
        with self._lock:
            entry = self._sessions.pop(session_id, None)
        if entry is not None:
            try:
                entry["engine"].close()
            except Exception:
                pass
            return True
        return False

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all active sessions with metadata."""
        self._cleanup_expired()
        with self._lock:
            result = []
            for sid, entry in self._sessions.items():
                engine: BaseEngine = entry["engine"]
                result.append({
                    "session_id": sid,
                    "engine_type": engine.engine_type,
                    "arch": engine.arch,
                    "label": entry.get("label", ""),
                    "created_at": entry["created_at"],
                    "last_activity": engine.last_activity,
                    "hooks": len(engine.hooks),
                    "snapshots": len(engine.snapshots),
                    "trace_entries": len(engine.trace),
                    "age_seconds": round(time.time() - entry["created_at"]),
                })
            return result

    def close_all(self) -> int:
        """Close all sessions. Returns count closed."""
        with self._lock:
            sids = list(self._sessions.keys())
        count = 0
        for sid in sids:
            if self.close(sid):
                count += 1
        return count

    _CLEANUP_INTERVAL_S: float = 30.0  # minimum seconds between cleanup passes

    def _cleanup_expired(self) -> None:
        """Remove sessions that have been idle too long.

        Rate-limited to at most once every 30 seconds so that high-frequency
        get() calls (e.g., tight emulation loops calling tools on every step)
        don't pay the cost of iterating all sessions under the lock each time.
        """
        now = time.time()
        if now - self._last_cleanup < self._CLEANUP_INTERVAL_S:
            return
        self._last_cleanup = now

        expired = []
        with self._lock:
            for sid, entry in self._sessions.items():
                if now - entry["engine"].last_activity > self.SESSION_TIMEOUT_S:
                    expired.append(sid)
        for sid in expired:
            self.close(sid)
