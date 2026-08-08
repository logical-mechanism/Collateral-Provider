import unittest
from unittest.mock import patch

from rest_framework.exceptions import ValidationError

from api.validators.environment import check_environment, check_ip_address


class TestEnvironmentValidator(unittest.TestCase):
    @patch("api.validators.environment.banned_ip_address", ["127.0.0.1"])
    def test_check_ip_address_banned(self):
        ip_address = "127.0.0.1"
        with self.assertRaises(ValidationError) as context:
            check_ip_address(ip_address)
        self.assertIn("Client IP Is Banned", str(context.exception.detail))
        self.assertNotIn(ip_address, str(context.exception.detail))

    def test_check_ip_address_allowed(self):
        # Not banned — must return without raising.
        check_ip_address("192.168.1.1")

    def test_check_environment_invalid(self):
        environment = "invalid_env"
        with self.assertRaises(ValidationError) as context:
            check_environment(environment, ["preprod", "mainnet"])
        self.assertIn(f"Invalid Environment: {environment}", str(context.exception.detail))

    def test_check_environment_valid(self):
        # Listed network — must return without raising.
        check_environment("mainnet", ["preprod", "mainnet"])
