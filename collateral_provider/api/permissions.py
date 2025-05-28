import ipaddress
from django.conf import settings
from rest_framework import permissions

def get_client_ip(request) -> str:
    """
    Mirror the helper in your view:
        1. Take the first entry in X-Forwarded-For if present.
        2. Otherwise fall back to REMOTE_ADDR.
    """
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")

def ip_matches(addr: str, patterns: list[str]) -> bool:
    """
    Return True iff *addr* is contained in **any** entry in *patterns*.
    Each entry may be either a plain IP (“203.0.113.42”) or a CIDR block
    (“198.51.100.0/24”). Invalid patterns are ignored.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False                           # malformed REMOTE_ADDR
    for pat in patterns:
        try:
            if ip in ipaddress.ip_network(pat, strict=False):
                return True
        except ValueError:
            continue                           # skip invalid pattern
    return False


class TokenRequiredFromIP(permissions.BasePermission):
    """
    Attach to any view that should enforce the rule.
    """

    def has_permission(self, request, view):
        # Skip the check entirely unless we are in production
        if getattr(settings, "ENVIRONMENT", "") != "production":
            return True

        client_ip = get_client_ip(request)
        token_ips = getattr(settings, "TOKEN_REQUIRED_IPS", [])

        # If IP is not in the protected list, allow the request (anon throttle still applies).
        if not ip_matches(client_ip, token_ips):
            return True

        # IP is in the list → user must already be authenticated.
        return bool(request.user and request.user.is_authenticated)
    
    
