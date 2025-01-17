from api.ban_list import banned_ip_address
from api.util import log_and_raise_error


class EnvironmentValidator:
    def __init__(self, logger):
        self.logger = logger

    def check_ip_address(self, ip_address):
        if ip_address in banned_ip_address:
            log_and_raise_error(self.logger, f"The IP: {ip_address} Is Banned")

    def check_environment(self, environment, networks):
        if environment not in networks:
            log_and_raise_error(self.logger, f"Invalid Environment: {environment}")
