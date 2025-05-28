# api/auth.py
import logging
from rest_framework.authentication import (
    TokenAuthentication, get_authorization_header
)
from rest_framework.exceptions import AuthenticationFailed

log = logging.getLogger("api.invalid_token")


class LoggingTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        # no header → anonymous
        if not auth or auth[0].lower() != b"token":
            return None

        if len(auth) == 1:
            self._log("<missing>", ok=False)
            raise AuthenticationFailed("Invalid token header. No credentials.")
        try:
            key = auth[1].decode()
        except UnicodeDecodeError:
            self._log("<non-utf8>", ok=False)
            raise AuthenticationFailed("Token string should be UTF-8.")

        # look-up key
        model = self.get_model()
        try:
            token = model.objects.select_related("user").get(key=key)
        except model.DoesNotExist:
            self._log(key, ok=False)
            raise AuthenticationFailed("Invalid token.")

        self._log(key, ok=True, user=token.user.username)
        return (token.user, token)

    def _log(self, key: str, ok: bool, user: str | None = None):
        """
        Write a line to the logger:
            [key]  OK|FAIL  [username]
        """
        status = "OK" if ok else "FAIL"
        who = f" user={user}" if user else ""
        log.warning("token=%s %s%s", key, status, who)
