"""Mtime-aware JSON reloader.

Both the ban list and the known-hosts registry are operator-curated data,
not code. We don't want a code deploy to be the latency for "ban this
scammer." Instead the operator edits the JSON file (atomic
write-tmp + rename is the expected workflow) and the service picks up
the new content on the next request.

The cost on the hot path is one ``os.path.getmtime`` syscall per access.
A reload only happens when the mtime has actually advanced.
"""

import json
import logging
import os
from threading import RLock

logger = logging.getLogger("api")


class MtimeReloadingJson:
    """Cache the parsed JSON of a file. Re-read if and only if the file's
    mtime has advanced since the last successful read.

    Behavior on edge cases:
    - File missing on first access: returns ``default``, doesn't crash.
    - File missing later: keeps the last successfully-loaded value and
      logs a warning. Surfaced as a stale cache rather than a service
      outage — operators pulling a file by accident shouldn't take the
      service down.
    - File present but unparseable: same. Logs ERROR; keeps last good.
    """

    def __init__(self, path: str, default):
        self._path = path
        self._default = default
        self._lock = RLock()
        self._mtime: float | None = None
        self._data = default

    @property
    def path(self) -> str:
        return self._path

    def get(self):
        try:
            mtime = os.path.getmtime(self._path)
        except FileNotFoundError:
            if self._mtime is not None:
                logger.warning("Reloadable file disappeared: %s", self._path)
            return self._data

        if self._mtime is not None and mtime <= self._mtime:
            return self._data

        with self._lock:
            # Re-check under lock in case another thread already reloaded.
            if self._mtime is not None and mtime <= self._mtime:
                return self._data
            try:
                with open(self._path) as f:
                    new_data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                logger.error("Failed to read %s: %s", self._path, exc)
                return self._data
            self._data = new_data
            self._mtime = mtime
            logger.info("Reloaded %s", self._path)
            return self._data
