import os
import tempfile

from django.test import SimpleTestCase, override_settings

from api.health import readiness_problems
from api.signature import _clear_key_cache


class ReadinessProblemsTest(SimpleTestCase):
    def setUp(self):
        _clear_key_cache()

    def _key_file(self, value: str, suffix: str) -> str:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as key:
            key.write('{"cborHex":"5820' + value + '"}')
        self.addCleanup(os.unlink, key.name)
        return key.name

    def _atomic_replace_key(self, path: str, value: str, mtime_ns: int) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".key",
            dir=os.path.dirname(path),
            delete=False,
        ) as replacement:
            replacement.write('{"cborHex":"5820' + value + '"}')
            replacement_path = replacement.name
        try:
            os.utime(replacement_path, ns=(mtime_ns, mtime_ns))
            os.replace(replacement_path, path)
        finally:
            if os.path.exists(replacement_path):
                os.unlink(replacement_path)

    def test_accepts_matching_identity(self):
        skey = self._key_file("00" * 32, ".skey")
        vkey = self._key_file(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            ".vkey",
        )
        with override_settings(
            SKEY_PATH=skey,
            VKEY_PATH=vkey,
            PKH="cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc41",
        ):
            self.assertEqual(readiness_problems(), [])

    def test_reports_public_safe_problem_for_mismatch(self):
        skey = self._key_file("00" * 32, ".skey")
        vkey = self._key_file("00" * 32, ".vkey")
        with override_settings(SKEY_PATH=skey, VKEY_PATH=vkey, PKH="00" * 28):
            self.assertEqual(readiness_problems(), ["signing identity invalid"])

    def test_detects_equal_mtime_atomic_key_replacement(self):
        skey = self._key_file("00" * 32, ".skey")
        vkey = self._key_file(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            ".vkey",
        )
        with override_settings(
            SKEY_PATH=skey,
            VKEY_PATH=vkey,
            PKH="cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc41",
        ):
            self.assertEqual(readiness_problems(), [])
            original = os.stat(vkey)
            self._atomic_replace_key(vkey, "00" * 32, original.st_mtime_ns)
            self.assertEqual(readiness_problems(), ["signing identity invalid"])
