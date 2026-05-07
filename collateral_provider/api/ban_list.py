"""Ban lists. Edit ``settings.BANS_PATH`` (default: ``BASE_DIR/bans.json``)
and the change is picked up on the next request — no redeploy needed.

The file's shape:

    {
      "addresses": ["<hex output address>", ...],
      "ips":       ["<v4 or v6 string>", ...]
    }

Address strings are the **raw output address bytes** in lowercase hex
(matching what ``check_outputs`` compares against), not bech32.
"""

from django.conf import settings

from api.data_files import MtimeReloadingJson

_DEFAULT = {"addresses": [], "ips": []}
_loader: MtimeReloadingJson | None = None


def _bans() -> dict:
    """Return the current bans dict. Re-uses one MtimeReloadingJson per
    distinct ``settings.BANS_PATH`` value so ``override_settings`` in tests
    rebuilds the loader against the test's file path."""
    global _loader
    path = settings.BANS_PATH
    if _loader is None or _loader.path != path:
        _loader = MtimeReloadingJson(path, default=_DEFAULT)
    return _loader.get()


class _BannedField:
    """Iterable + ``in``-checkable proxy that re-reads the bans file each
    time it's used. Looks like a list at the call site so existing code
    doesn't change shape."""

    __slots__ = ("_key",)

    def __init__(self, key: str):
        self._key = key

    def __contains__(self, item) -> bool:
        return item in _bans().get(self._key, [])

    def __iter__(self):
        return iter(_bans().get(self._key, []))

    def __len__(self) -> int:
        return len(_bans().get(self._key, []))


banned_addresses = _BannedField("addresses")
banned_ip_address = _BannedField("ips")
