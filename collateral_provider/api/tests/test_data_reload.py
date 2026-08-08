"""Verify that bans.json and known.hosts.json are read at request time
(with stat-identity-aware caching), so an operator can edit them without
bouncing the service.
"""

import contextlib
import hashlib
import json
import os
import tempfile
import time
import unittest

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from api.data_files import MtimeReloadingJson

TEST_PUBLIC_KEY = "754c1db51aaee2e939b05b529ff5e210d8469afebcd2e487dae6f125fd500356"
TEST_PKH = hashlib.blake2b(bytes.fromhex(TEST_PUBLIC_KEY), digest_size=28).hexdigest()


def _make_tmp_path() -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        return f.name


def _write_json(path: str, data) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


def _atomic_write_json(path: str, data, *, mtime_ns: int) -> None:
    directory = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as f:
        json.dump(data, f)
        replacement = f.name
    try:
        os.utime(replacement, ns=(mtime_ns, mtime_ns))
        os.replace(replacement, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(replacement)


def _valid_registry(
    url: str = "https://example.test/preprod/collateral/",
    *,
    pkh: str = TEST_PKH,
    public_key: str = TEST_PUBLIC_KEY,
) -> dict:
    return {
        pkh: {
            "preprod": {
                "url": url,
                "utxo": {"id": "ab" * 32, "idx": 0},
            },
            "public_key": public_key,
        },
    }


def _bump_mtime(path: str) -> None:
    # Force a noticeable mtime tick. Some filesystems have second-level
    # mtime granularity, so we sleep then re-stamp via os.utime.
    time.sleep(0.01)
    now = time.time()
    os.utime(path, (now, now))


class TestMtimeReloadingJson(unittest.TestCase):
    def setUp(self):
        self.path = _make_tmp_path()

    def tearDown(self):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)

    def test_returns_default_when_file_missing(self):
        os.unlink(self.path)
        loader = MtimeReloadingJson(self.path, default={"x": 1})
        self.assertEqual(loader.get(), {"x": 1})

    def test_loads_initial_content(self):
        _write_json(self.path, {"hello": "world"})
        loader = MtimeReloadingJson(self.path, default={})
        self.assertEqual(loader.get(), {"hello": "world"})

    def test_reloads_when_mtime_advances(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(self.path, default={})
        self.assertEqual(loader.get()["v"], 1)

        _write_json(self.path, {"v": 2})
        _bump_mtime(self.path)
        self.assertEqual(loader.get()["v"], 2)

    def test_does_not_reread_when_mtime_unchanged(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(self.path, default={})
        loader.get()
        before = os.stat(self.path)
        _write_json(self.path, {"v": 2})
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(loader.get()["v"], 1)

    def test_reloads_equal_mtime_atomic_replacement(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(self.path, default={})
        self.assertEqual(loader.get(), {"v": 1})
        original = os.stat(self.path)

        _atomic_write_json(self.path, {"v": 2}, mtime_ns=original.st_mtime_ns)

        replacement = os.stat(self.path)
        self.assertNotEqual(replacement.st_ino, original.st_ino)
        self.assertEqual(replacement.st_mtime_ns, original.st_mtime_ns)
        self.assertEqual(loader.get(), {"v": 2})

    def test_reloads_older_mtime_atomic_replacement(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(self.path, default={})
        self.assertEqual(loader.get(), {"v": 1})
        original = os.stat(self.path)
        older_mtime_ns = max(0, original.st_mtime_ns - 1_000_000_000)

        _atomic_write_json(self.path, {"v": 2}, mtime_ns=older_mtime_ns)

        self.assertLessEqual(os.stat(self.path).st_mtime_ns, original.st_mtime_ns)
        self.assertEqual(loader.get(), {"v": 2})

    def test_keeps_last_good_value_when_file_disappears(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(self.path, default={"sentinel": True})
        loader.get()
        os.unlink(self.path)
        self.assertEqual(loader.get(), {"v": 1})

    def test_keeps_last_good_value_on_invalid_json(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(self.path, default={})
        loader.get()
        with open(self.path, "w") as f:
            f.write("{not json")
        _bump_mtime(self.path)
        self.assertEqual(loader.get()["v"], 1)

    def test_keeps_last_good_value_on_schema_failure(self):
        _write_json(self.path, {"v": 1})
        loader = MtimeReloadingJson(
            self.path,
            default={},
            validator=lambda value: isinstance(value, dict),
        )
        loader.get()
        _write_json(self.path, ["syntactically-valid", "wrong-shape"])
        _bump_mtime(self.path)
        self.assertEqual(loader.get(), {"v": 1})


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestBansHotReload(TestCase):
    """Bans should be picked up from the file without restarting the
    service. Operator updates a bans.json -> next request honors it."""

    def setUp(self):
        self.path = _make_tmp_path()
        self.client = APIClient()

    def tearDown(self):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)

    def test_ip_ban_picked_up_from_file(self):
        from rest_framework.exceptions import ValidationError

        from api.validators.environment import check_ip_address

        _write_json(self.path, {"addresses": [], "ips": ["10.0.0.42"]})
        _bump_mtime(self.path)
        with override_settings(BANS_PATH=self.path):
            with self.assertRaises(ValidationError):
                check_ip_address("10.0.0.42")
            check_ip_address("10.0.0.99")

    def test_address_ban_picked_up_from_file(self):
        from rest_framework.exceptions import ValidationError

        from api.validators.cbor import check_outputs

        addr_hex = "70" + "ab" * 28
        _write_json(self.path, {"addresses": [addr_hex], "ips": []})
        _bump_mtime(self.path)

        body = {1: [[bytes.fromhex(addr_hex), 1_000_000]]}
        with override_settings(BANS_PATH=self.path):
            with self.assertRaises(ValidationError) as ctx:
                check_outputs(body)
            self.assertIn("Is Banned", str(ctx.exception.detail))

    def test_unbanning_takes_effect_after_file_update(self):
        from rest_framework.exceptions import ValidationError

        from api.validators.environment import check_ip_address

        _write_json(self.path, {"addresses": [], "ips": ["10.0.0.42"]})
        _bump_mtime(self.path)
        with override_settings(BANS_PATH=self.path):
            with self.assertRaises(ValidationError):
                check_ip_address("10.0.0.42")

            _write_json(self.path, {"addresses": [], "ips": []})
            _bump_mtime(self.path)

            # Same call now passes — no service restart needed.
            check_ip_address("10.0.0.42")

    def test_missing_file_means_no_bans(self):
        os.unlink(self.path)
        from api.validators.environment import check_ip_address
        with override_settings(BANS_PATH=self.path):
            check_ip_address("10.0.0.42")  # passes

    def test_invalid_schema_keeps_last_good_bans(self):
        from rest_framework.exceptions import ValidationError

        from api.validators.environment import check_ip_address

        _write_json(self.path, {"addresses": [], "ips": ["10.0.0.42"]})
        _bump_mtime(self.path)
        with override_settings(BANS_PATH=self.path):
            with self.assertRaises(ValidationError):
                check_ip_address("10.0.0.42")

            _write_json(self.path, ["wrong", "top-level", "shape"])
            _bump_mtime(self.path)

            with self.assertRaises(ValidationError):
                check_ip_address("10.0.0.42")


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestKnownHostsHotReload(TestCase):
    def setUp(self):
        self.path = _make_tmp_path()
        self.client = APIClient()

    def tearDown(self):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)

    def test_landing_page_picks_up_new_hosts(self):
        from django.conf import settings as live_settings

        from api.signature import get_key_from_file

        def _entry(url):
            return _valid_registry(
                url,
                pkh=live_settings.PKH,
                public_key=get_key_from_file(live_settings.VKEY_PATH),
            )

        _write_json(self.path, _entry("https://v1.example.test/preprod/collateral/"))
        _bump_mtime(self.path)

        with override_settings(KNOWN_HOSTS_PATH=self.path):
            response = self.client.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"v1", response.content)

            _write_json(self.path, _entry("https://v2.example.test/preprod/collateral/"))
            _bump_mtime(self.path)

            response = self.client.get("/")
            self.assertIn(b"v2", response.content)

    def test_known_hosts_endpoint_returns_empty_when_file_missing(self):
        os.unlink(self.path)
        with override_settings(KNOWN_HOSTS_PATH=self.path):
            response = self.client.get(reverse("known_hosts"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})

    def test_invalid_registry_shape_keeps_last_good_document(self):
        original = _valid_registry()
        _write_json(self.path, original)
        _bump_mtime(self.path)

        with override_settings(KNOWN_HOSTS_PATH=self.path):
            self.assertEqual(self.client.get(reverse("known_hosts")).json(), original)

            _write_json(self.path, ["not", "a", "registry"])
            _bump_mtime(self.path)

            response = self.client.get(reverse("known_hosts"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), original)

    def test_invalid_nested_registry_keeps_last_good_document(self):
        original = _valid_registry()
        _write_json(self.path, original)
        _bump_mtime(self.path)

        with override_settings(KNOWN_HOSTS_PATH=self.path):
            self.assertEqual(self.client.get(reverse("known_hosts")).json(), original)

            invalid = _valid_registry("http://example.test/preprod/collateral/")
            _write_json(self.path, invalid)
            _bump_mtime(self.path)

            response = self.client.get(reverse("known_hosts"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), original)
