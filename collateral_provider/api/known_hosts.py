"""Validation for the public collateral-provider registry."""

import hashlib
import re
from urllib.parse import urlsplit

_PKH_RE = re.compile(r"[0-9a-f]{56}")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}")
_TXID_RE = re.compile(r"[0-9a-f]{64}")
_NETWORK_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")


def _validate_endpoint_url(url: object, network: str, location: str) -> None:
    if not isinstance(url, str) or not url:
        raise ValueError(f"{location}.url must be a non-empty string")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in url):
        raise ValueError(f"{location}.url must contain only visible ASCII characters")
    if "\\" in url:
        raise ValueError(f"{location}.url may not contain backslashes")

    try:
        parsed = urlsplit(url)
        # Accessing port performs urllib's range and numeric validation.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{location}.url is malformed") from exc

    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
        raise ValueError(f"{location}.url must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{location}.url may not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{location}.url may not contain a query or fragment")
    expected_path = f"/{network}/collateral"
    if parsed.path.rstrip("/") != expected_path:
        raise ValueError(
            f"{location}.url path must be {expected_path}/ (trailing slash optional)"
        )


def validate_known_hosts_registry(value: object) -> None:
    """Raise ``ValueError`` unless ``value`` matches the registry contract.

    The registry is consumed directly by wallets and the landing page, so a
    partially valid document is not useful. Hot reload keeps serving the last
    entirely valid document when an operator update fails this validation.
    """
    if not isinstance(value, dict):
        raise ValueError("registry must be an object keyed by provider PKH")

    for pkh, provider in value.items():
        if not isinstance(pkh, str) or _PKH_RE.fullmatch(pkh) is None:
            raise ValueError("provider PKH keys must be 56 lowercase hexadecimal characters")
        location = f"provider {pkh}"
        if not isinstance(provider, dict):
            raise ValueError(f"{location} must be an object")

        public_key = provider.get("public_key")
        if (
            not isinstance(public_key, str)
            or _PUBLIC_KEY_RE.fullmatch(public_key) is None
        ):
            raise ValueError(
                f"{location}.public_key must be 64 lowercase hexadecimal characters"
            )
        derived_pkh = hashlib.blake2b(bytes.fromhex(public_key), digest_size=28).hexdigest()
        if derived_pkh != pkh:
            raise ValueError(f"{location}.public_key does not derive its PKH")

        network_entries = {
            network: config
            for network, config in provider.items()
            if network != "public_key"
        }
        if not network_entries:
            raise ValueError(f"{location} must advertise at least one network")

        for network, config in network_entries.items():
            network_location = f"{location}.{network}"
            if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
                raise ValueError(f"{location} contains an invalid network name")
            if not isinstance(config, dict) or set(config) != {"utxo", "url"}:
                raise ValueError(
                    f"{network_location} must contain exactly 'utxo' and 'url'"
                )

            utxo = config["utxo"]
            if not isinstance(utxo, dict) or set(utxo) != {"id", "idx"}:
                raise ValueError(
                    f"{network_location}.utxo must contain exactly 'id' and 'idx'"
                )
            txid = utxo["id"]
            txidx = utxo["idx"]
            if not isinstance(txid, str) or _TXID_RE.fullmatch(txid) is None:
                raise ValueError(
                    f"{network_location}.utxo.id must be 64 lowercase hexadecimal characters"
                )
            if (
                not isinstance(txidx, int)
                or isinstance(txidx, bool)
                or txidx < 0
            ):
                raise ValueError(
                    f"{network_location}.utxo.idx must be a non-negative integer"
                )

            _validate_endpoint_url(config["url"], network, network_location)
