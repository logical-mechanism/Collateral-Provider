"""The throttle cache must not forget counters under load.

``FileBasedCache`` defaults to ``MAX_ENTRIES=300`` / ``CULL_FREQUENCY=3``, and
``set()`` calls ``_cull()`` on every write. Past 300 keys that deletes a random
third of them — and each throttled client IP is one key, so the only abuse
control on an unauthenticated endpoint quietly stopped counting under exactly
the traffic it exists to bound. ``settings.CACHES['default']['OPTIONS']`` raises
the ceiling well above any plausible number of concurrent source IPs.
"""

import shutil
import tempfile

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings


def _file_cache(location, **options):
    return {
        "default": {
            "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
            "LOCATION": location,
            **({"OPTIONS": options} if options else {}),
        }
    }


class ThrottleCacheRetentionTestCase(SimpleTestCase):
    def setUp(self):
        self.location = tempfile.mkdtemp(prefix="throttle-cache-test-")
        self.addCleanup(shutil.rmtree, self.location, ignore_errors=True)

    def test_configured_options_are_in_effect(self):
        from django.conf import settings

        options = settings.CACHES["default"].get("OPTIONS", {})
        # Well above Django's 300 default, but bounded: _cull() globs the
        # whole directory on every set(), so the ceiling is also a
        # per-request cost (measured ~1.6 ms at 2000, ~17 ms at 20000).
        self.assertGreaterEqual(options.get("MAX_ENTRIES", 0), 2000)
        self.assertLessEqual(options.get("MAX_ENTRIES", 0), 5000)

    def test_counter_survives_far_more_client_ips_than_djangos_default(self):
        """A busy IP's counter must outlive 500 one-shot IPs."""
        with override_settings(CACHES=_file_cache(self.location, MAX_ENTRIES=2000)):
            cache.set("throttle_anon_busy", [1, 2, 3], 600)
            for index in range(500):
                cache.set(f"throttle_anon_churn_{index}", [1], 600)

            self.assertEqual(cache.get("throttle_anon_busy"), [1, 2, 3])

    def test_djangos_default_ceiling_would_have_dropped_it(self):
        """Characterize the behaviour the OPTIONS exist to prevent.

        Culling is random, so this asserts the population collapses rather than
        that one specific key vanished — that is the property that made the
        throttle unreliable.
        """
        with override_settings(CACHES=_file_cache(self.location + "-default")):
            for index in range(500):
                cache.set(f"throttle_anon_churn_{index}", [1], 600)

            survivors = sum(
                1
                for index in range(500)
                if cache.get(f"throttle_anon_churn_{index}") is not None
            )
            self.assertLess(survivors, 400)
