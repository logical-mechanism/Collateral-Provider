"""Stat-identity-aware JSON reloader.

Both the ban list and the known-hosts registry are operator-curated data,
not code. We don't want a code deploy to be the latency for "ban this
scammer." Instead the operator edits the JSON file (atomic
write-tmp + rename is the expected workflow) and the service picks up
the new content on the next request.

The cost on the hot path is one ``os.stat`` syscall per access. A reload
happens whenever ``(mtime_ns, size, inode)`` changes, including atomic
replacements whose timestamp is equal to or older than the previous file.
"""

import json
import logging
import os
from collections.abc import Callable
from threading import RLock

logger = logging.getLogger("api")

type FileIdentity = tuple[int, int, int]


def stat_identity(stat_result: os.stat_result) -> FileIdentity:
    """Return the fields that identify the observed contents of a file."""
    return (stat_result.st_mtime_ns, stat_result.st_size, stat_result.st_ino)


def file_identity(path: str) -> FileIdentity:
    """Stat ``path`` and return its reload identity."""
    return stat_identity(os.stat(path))


class MtimeReloadingJson:
    """Cache the parsed JSON of a file and re-read when its identity changes.

    Behavior on edge cases:
    - File missing on first access: returns ``default``, doesn't crash.
    - File missing later: keeps the last successfully-loaded value and
      logs a warning. Surfaced as a stale cache rather than a service
      outage — operators pulling a file by accident shouldn't take the
      service down.
    - File present but unparseable: same. Logs ERROR; keeps last good.
    """

    def __init__(
        self,
        path: str,
        default,
        validator: Callable[[object], None] | None = None,
    ):
        """``validator`` signals rejection by raising ``ValueError``.

        There is exactly one contract, deliberately. Accepting a boolean
        return as well meant a validator that fell off the end without an
        explicit ``return`` published the invalid document as live data with
        no log line — the failure mode is silent, and both shapes are easy to
        write by accident.
        """
        self._path = path
        self._default = default
        self._validator = validator
        self._lock = RLock()
        self._identity: FileIdentity | None = None
        self._data = default

    @property
    def path(self) -> str:
        return self._path

    def get(self):
        try:
            identity = file_identity(self._path)
        except FileNotFoundError:
            if self._identity is not None:
                logger.warning("Reloadable file disappeared: %s", self._path)
            return self._data
        except OSError as exc:
            logger.error("Failed to stat %s: %s", self._path, exc)
            return self._data

        if self._identity == identity:
            return self._data

        with self._lock:
            # Re-check under lock in case another thread already reloaded.
            try:
                identity = file_identity(self._path)
            except OSError as exc:
                logger.error("Failed to stat %s: %s", self._path, exc)
                return self._data
            if self._identity == identity:
                return self._data
            attempted_identity = identity
            try:
                with open(self._path) as f:
                    # Cache the identity of the file descriptor we actually
                    # parsed. If the path is atomically replaced after open,
                    # the next access sees the new path identity and reloads.
                    attempted_identity = stat_identity(os.fstat(f.fileno()))
                    new_data = json.load(f)
                if self._validator is not None:
                    self._validator(new_data)
            except OSError as exc:
                logger.error("Failed to read %s: %s", self._path, exc)
                return self._data
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                # Avoid reparsing and relogging the exact same bad operator
                # update on every request. Any in-place correction changes
                # mtime/size; an atomic correction changes the inode.
                self._identity = attempted_identity
                logger.error("Rejected invalid data in %s: %s", self._path, exc)
                return self._data
            self._data = new_data
            self._identity = attempted_identity
            logger.info("Reloaded %s", self._path)
            return self._data
