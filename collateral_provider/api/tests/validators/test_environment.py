import unittest
from unittest.mock import Mock, patch

from api.validators.environment import EnvironmentValidator
from rest_framework.exceptions import ValidationError


class TestEnvironmentValidator(unittest.TestCase):

    def setUp(self):
        # Create a mock logger
        self.mock_logger = Mock()
        # Initialize EnvironmentValidator with the mock logger
        self.validator = EnvironmentValidator(self.mock_logger)

    @patch("api.validators.environment.banned_ip_address", ["127.0.0.1"])
    def test_check_ip_address_banned(self):
        ip_address = "127.0.0.1"
        with self.assertRaises(ValidationError) as context:
            self.validator.check_ip_address(ip_address)

        # Extract the error message from the ValidationError
        self.assertIn(f"{ip_address} Is Banned", str(context.exception.detail))

    def test_check_ip_address_allowed(self):
        # Test for an allowed IP
        ip_address = "192.168.1.1"
        try:
            self.validator.check_ip_address(ip_address)
        except ValidationError:
            self.fail("check_ip_address raised ValidationError unexpectedly!")

    def test_check_environment_invalid(self):
        environment = "invalid_env"
        networks = ["preprod", "mainnet"]
        with self.assertRaises(ValidationError) as context:
            self.validator.check_environment(environment, networks)

        # Extract the error message from the ValidationError
        self.assertIn(f"Invalid Environment: {environment}", str(context.exception.detail))

    def test_check_environment_valid(self):
        # Test for a valid environment
        environment = "mainnet"
        networks = ["preprod", "mainnet"]
        try:
            self.validator.check_environment(environment, networks)
        except ValidationError:
            self.fail("check_environment raised ValidationError unexpectedly!")
