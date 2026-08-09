import os
from pathlib import Path

import environ

# Single source of truth for the service version. /healthz reports it, the
# OpenAPI schema reports it. Bump on any externally-visible change.
from api import __version__ as API_VERSION
from api.log_format import build_logging_config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Configuration is read from process environment, with a .env file as an
# optional convenience for local development. Container-platform deploys
# (DigitalOcean App Platform, Heroku-style PaaS, Kubernetes) inject
# variables directly via os.environ — there is no .env file in those
# environments, and that is fine. The required-vars check below still
# fails loudly if anything actually needed is unset.
env = environ.Env()
env_file = os.path.join(BASE_DIR, '.env')
if os.path.exists(env_file):
    environ.Env.read_env(env_file)

# Identity / signing material. Both key paths default to the api/key dir
# bundled with the repo (used in dev and tests); production deploys should
# override SKEY_PATH and VKEY_PATH to point at locations outside the
# checkout (e.g. /etc/collateral-provider/keys).
def _canonical_hex(value: str, name: str, expected_bytes: int | None = None) -> str:
    """Normalize an operator-supplied hex value, or refuse to start.

    Startup validation and /healthz both parse these with ``bytes.fromhex``,
    which tolerates uppercase and silently skips ASCII whitespace. Every
    request-time comparison is an exact lowercase string match instead, so an
    uppercase or space-padded value produced a service that reported itself
    healthy and then rejected 100% of traffic with a message blaming the
    caller. Canonicalizing once, here, keeps both paths agreeing.
    """
    text = ''.join(value.split()).lower()
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be hexadecimal, got {value!r}") from exc
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise RuntimeError(
            f"{name} must be exactly {expected_bytes} bytes ({expected_bytes * 2} hex characters)"
        )
    return text


PKH = _canonical_hex(env('PKH'), 'PKH', 28)
SKEY_PATH = env('SKEY_PATH', default=str(BASE_DIR / 'api' / 'key' / 'payment.skey'))
VKEY_PATH = env('VKEY_PATH', default=str(BASE_DIR / 'api' / 'key' / 'payment.vkey'))
SECRET_KEY = env('DJANGO_SECRET_KEY')
ENVIRONMENT = env('ENVIRONMENT')

# Per-network configuration. KOIOS_URL is the JSON-RPC Ogmios endpoint used
# for protocol-parameter lookup and evaluateTransaction. Defaults match Koios's
# public hosting for preprod/mainnet; override for a self-hosted evaluator or
# alternate networks (preview, sanchonet, ...).
ENVIRONMENTS = {
    'preprod': {
        'NETWORK': env('PREPROD_NETWORK'),
        # Canonicalized for the same reason as PKH: check_collateral compares
        # this against utxo[0].hex(), which is always lowercase. Length is not
        # enforced here so a local dev setup can leave a network blank; apps.py
        # enforces it for every non-development environment.
        'TXID': _canonical_hex(env('PREPROD_TXID'), 'PREPROD_TXID'),
        'TXIDX': env.int('PREPROD_TXIDX'),
        'KOIOS_URL': env(
            'PREPROD_KOIOS_URL',
            default='https://preprod.koios.rest/api/v1/ogmios',
        ),
    },
    'mainnet': {
        'NETWORK': env('MAINNET_NETWORK'),
        'TXID': _canonical_hex(env('MAINNET_TXID'), 'MAINNET_TXID'),
        'TXIDX': env.int('MAINNET_TXIDX'),
        'KOIOS_URL': env(
            'MAINNET_KOIOS_URL',
            default='https://api.koios.rest/api/v1/ogmios',
        ),
    },
}

# False is production
DEBUG = False

if ENVIRONMENT == "development":
    ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
else:
    ALLOWED_HOSTS = env.list('ALLOWED_HOSTS')
    if not ALLOWED_HOSTS:
        raise RuntimeError(
            "ALLOWED_HOSTS env var is empty in non-development mode — every "
            "request would be rejected. Refusing to start."
        )

# We're behind a TLS-terminating reverse proxy in production. Trust the
# X-Forwarded-Proto header so request.is_secure() works correctly. The proxy
# is also responsible for HSTS and HTTP -> HTTPS redirects.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Collateral endpoint throttle (per anonymous IP).
#
# A wallet backend proxying its users reaches us from a single egress IP, so
# this rate is that integrator's *entire* budget, not one user's. The former
# 60/min default capped a whole wallet at one request per second. 300/min
# leaves room for a real integrator while staying below the service's own
# upstream ceiling (KOIOS_MAX_IN_FLIGHT * workers, ~8-32 rps depending on
# evaluator latency), so a single abusive IP still cannot monopolise it.
# Operators fronting a known partner should raise this further.
COLLATERAL_THROTTLE_RATE = env('COLLATERAL_THROTTLE_RATE', default='300/min')

# Per-process admission budget for outbound Koios calls. Gunicorn runs two
# processes, so the default bounds aggregate in-flight upstream calls to about
# eight while leaving worker threads available for health checks and fast
# rejections during an upstream slowdown.
KOIOS_MAX_IN_FLIGHT = env.int('KOIOS_MAX_IN_FLIGHT', default=4)
if KOIOS_MAX_IN_FLIGHT < 1:
    raise RuntimeError("KOIOS_MAX_IN_FLIGHT must be at least 1")

# X-Forwarded-For is only trusted when the immediate connection (i.e. the
# REMOTE_ADDR Django sees) is one of these IPs. Defaults to localhost,
# which is right when nginx/Caddy lives on the same host. Multi-host
# deploys should list every load-balancer / reverse-proxy egress IP.
# An empty list disables XFF trust entirely.
TRUSTED_PROXY_IPS = env.list('TRUSTED_PROXY_IPS', default=['127.0.0.1', '::1'])

# Operator-curated data files. The service stats them on every request and
# re-parses when (mtime_ns, size, inode) changes. Default locations put them
# next to the project (gitignored) so editing + atomic-rename is the operator
# workflow.
BANS_PATH = env('BANS_PATH', default=str(BASE_DIR / 'bans.json'))
KNOWN_HOSTS_PATH = env(
    'KNOWN_HOSTS_PATH',
    default=str(BASE_DIR.parent / 'known.hosts.json'),
)

# Prometheus /metrics. Off by default — when off, the URL 404s. When on,
# only IPs in METRICS_ALLOW_IPS (default: localhost) can reach it. Run
# your scraper on the same host or behind a private network.
METRICS_ENABLED = env.bool('METRICS_ENABLED', default=False)
METRICS_ALLOW_IPS = env.list('METRICS_ALLOW_IPS', default=['127.0.0.1', '::1'])

INSTALLED_APPS = [
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_spectacular',
    'corsheaders',
    'api',
]

# We don't use sessions, auth, or CSRF — this is a stateless public POST API.
# Skip the corresponding middleware so each request doesn't pay for them.
# Disallowed-host responses are formatted by handler400 in urls.py; we rely
# on Django's built-in ALLOWED_HOSTS check rather than a custom middleware.
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # must precede CommonMiddleware
    'api.middleware.RequestIDMiddleware',     # stamp X-Request-ID before anything logs
    'api.middleware.MetricsMiddleware',       # measure /collateral request count + duration
    'api.middleware.RequestBodyLimitMiddleware',  # cap bytes before DRF parses JSON
    'django.middleware.security.SecurityMiddleware',
    # Whitenoise serves the collected static files directly from gunicorn.
    # Required because containerized deploys (DO App Platform, etc.) don't
    # have a separate static-file server in front. Must sit immediately
    # after SecurityMiddleware per Whitenoise docs.
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'collateral_provider.urls'

WSGI_APPLICATION = 'collateral_provider.wsgi.application'

# Required by DRF's browsable API and our HTML landing page. The auth and
# messages context processors aren't applicable (no auth, no messages app).
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
            ],
        },
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# DRF's AnonRateThrottle stores per-IP request counts in the Django cache.
# The default LocMemCache is per-process — under multi-worker gunicorn each
# worker has its own counter, so the real ceiling is N*rate. File-based cache
# shares state across workers on the same host without requiring Redis.
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': env('CACHE_DIR', default=os.path.join(BASE_DIR, '.cache')),
        'TIMEOUT': 600,
        # Django's defaults here are MAX_ENTRIES=300 / CULL_FREQUENCY=3, which
        # means every write past 300 keys deletes a random third of them. Since
        # each throttled client IP is one key, the only abuse control on this
        # endpoint would quietly stop counting under exactly the traffic it
        # exists to bound.
        #
        # The ceiling cannot simply be raised, because FileBasedCache._cull()
        # globs the entire cache directory on *every* set() before its
        # early return, and expired files are only reclaimed by a cull or a
        # read. Measured glob cost per set(): 0.25 ms at 300 files, 1.6 ms at
        # 2000, 4.0 ms at 5000, 17 ms at 20000 — against roughly 2.4 ms of
        # total local CPU per request. 2000 buys ~6.7x the default headroom
        # (far more distinct client IPs than this service sees in the 60 s
        # throttle window) while keeping the per-request cost below the work
        # the request was already doing. Cull gently when it is reached.
        'OPTIONS': {
            'MAX_ENTRIES': 2000,
            'CULL_FREQUENCY': 10,
        },
    }
}

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# DRF defaults. We do not set DEFAULT_THROTTLE_CLASSES — every endpoint
# states its own throttling explicitly (or @throttle_classes([])).
# A global default is a footgun: a new endpoint would silently inherit
# whatever rate is in effect.
REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'EXCEPTION_HANDLER': 'api.util.normalize_error_response',
    'DEFAULT_THROTTLE_RATES': {
        'anon': COLLATERAL_THROTTLE_RATE,  # only consulted by AnonRateThrottle subclasses
    },
    # No auth — this is an open POST API. Disabling DRF's default auth
    # classes (SessionAuthentication, BasicAuthentication) lets us drop
    # django.contrib.auth + contenttypes from INSTALLED_APPS, since
    # those classes lazily import auth.User.
    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'UNAUTHENTICATED_USER': None,
    # JSON only. Form/multipart parsers are documented surface area we
    # don't use, and a multipart upload of `tx=<cbor>` would otherwise
    # succeed silently. Locking to JSON also makes the 415 response
    # consistent with the OpenAPI spec.
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    # JSON only, mirroring DEFAULT_PARSER_CLASSES. Without this DRF's default
    # [JSONRenderer, BrowsableAPIRenderer] applies, and any client sending
    # `Accept: text/html` — a browser, a curl default, an SDK that forwards the
    # user's header — receives an HTML page instead of the documented
    # {"detail": "..."} envelope, on success and error alike.
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    # With a single renderer, DRF's default negotiation answers 406 to anyone
    # asking for text/html. Pin JSON instead so the response shape depends on
    # the endpoint, not on the caller's Accept header.
    'DEFAULT_CONTENT_NEGOTIATION_CLASS': 'api.negotiation.JSONOnlyContentNegotiation',
}

# Protocol-adjacent cap. ``MAX_TX_SIZE`` matches the on-chain Conway protocol
# parameter (16 KiB binary) and is env-overridable so a future hard fork does
# not require a code deploy. The HTTP body cap allows the hex encoding plus a
# small JSON envelope; caller-supplied UTxOs are intentionally unsupported.
MAX_TX_SIZE = env.int('MAX_TX_SIZE', default=16 * 1024)

# Body = hex tx (2x binary) + 4 KiB for field names, JSON quoting, and slack.
# ``RequestBodyLimitMiddleware`` rejects anything larger before DRF parses JSON
# or the view runs, so junk cannot burn serializer/CBOR CPU.
DATA_UPLOAD_MAX_MEMORY_SIZE = (MAX_TX_SIZE * 2) + 4 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = DATA_UPLOAD_MAX_MEMORY_SIZE

SPECTACULAR_SETTINGS = {
    'TITLE': 'Cardano Collateral Provider API',
    'DESCRIPTION': (
        'Submit a Cardano transaction CBOR. If the transaction satisfies the '
        'collateral-usage contract (uses this provider\'s collateral UTxO, '
        'requires this provider\'s PKH as a signer, does not spend the '
        'collateral, has is_valid=true, binds the submitted script data and '
        'execution budgets, and passes phase-2 script evaluation), the '
        'service returns a vkey witness CBOR you can attach to the witness set.'
    ),
    'VERSION': API_VERSION,
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
}

CORS_ALLOW_ALL_ORIGINS = True

# Logging. File output remains the default (rotated at 1 MiB x 3 backups).
# LOG_TO_CONSOLE switches exclusively to stderr for systemd/journald and
# container runtimes; the file handler is not instantiated in that mode.
# LOG_FORMAT picks plain text (default) or JSON-per-line.
LOG_LEVEL = env('LOG_LEVEL', default='DEBUG')
LOG_FILE = env('LOG_FILE', default=str(BASE_DIR / 'debug.log'))
LOG_FORMAT = env('LOG_FORMAT', default='text')  # 'text' or 'json'
LOG_TO_CONSOLE = env.bool('LOG_TO_CONSOLE', default=False)
if LOG_FORMAT not in ('text', 'json'):
    raise RuntimeError(f"LOG_FORMAT must be 'text' or 'json', got {LOG_FORMAT!r}")

# Every record gets a request_id field via the RequestIDLogFilter, which
# reads from a contextvar set by RequestIDMiddleware. Outside a request
# (startup, management commands) the id is "-".
LOGGING = build_logging_config(
    log_level=LOG_LEVEL,
    log_file=LOG_FILE,
    log_format=LOG_FORMAT,
    log_to_console=LOG_TO_CONSOLE,
)

# This is a stateless POST API — no sessions, no CSRF, no auth cookies.
# TLS, HSTS, and HTTP->HTTPS redirects are all handled by the reverse proxy
# in front of gunicorn, so we don't set the SECURE_* / SESSION_* / CSRF_*
# flags here. SECURE_PROXY_SSL_HEADER above is what makes that delegation
# safe (Django will trust the proxy's Forwarded-Proto header).

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # This is your static folder
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Whitenoise: gzip/brotli-compress the collected static assets so the
# wire bytes are small. We do NOT use the manifest variant (which would
# hash filenames) because it requires `collectstatic` to have run before
# anything renders a `{% static %}` tag — that breaks the test suite,
# which doesn't run collectstatic. The static surface here is tiny
# (favicons + DRF browsable-API CSS) so the cache-busting story is fine
# without filename hashing.
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedStaticFilesStorage',
    },
}
