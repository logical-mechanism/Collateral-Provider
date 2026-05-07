from api.ban_list import banned_ip_address
from api.util import raise_validation_error


def check_ip_address(ip_address: str) -> None:
    if ip_address in banned_ip_address:
        raise_validation_error(f"The IP: {ip_address} Is Banned")


def check_environment(environment: str, networks: list[str]) -> None:
    if environment not in networks:
        raise_validation_error(f"Invalid Environment: {environment}")
