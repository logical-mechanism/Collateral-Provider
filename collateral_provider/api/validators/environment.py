from api.ban_list import banned_ip_address
from api.util import raise_validation_error


def check_ip_address(ip_address: str | None) -> None:
    if ip_address in banned_ip_address:
        # The exact value is already available transiently for the lookup and
        # throttle. Do not persist it through the shared validation logger.
        raise_validation_error("Client IP Is Banned")


def check_environment(environment: str, networks: list[str]) -> None:
    if environment not in networks:
        raise_validation_error(f"Invalid Environment: {environment}")
