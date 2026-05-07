import os
import sys
from pathlib import Path

import environ

# Single source of truth for the service version. /healthz reports it, the
# OpenAPI schema reports it. Bump on any externally-visible change.
from api import __version__ as API_VERSION

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Initialize environment variables
env_file = os.path.join(BASE_DIR, '.env')

# Check if the .env file exists
if not os.path.exists(env_file):
    print(f"Error: .env file is missing at {env_file}. Exiting.")
    sys.exit(1)  # Exit the application with a non-zero status code

env = environ.Env()
environ.Env.read_env(env_file)

# Identity / signing material. Both key paths default to the api/key dir
# bundled with the repo (used in dev and tests); production deploys should
# override SKEY_PATH and VKEY_PATH to point at locations outside the
# checkout (e.g. /etc/collateral-provider/keys).
PKH = env('PKH')
SKEY_PATH = env('SKEY_PATH', default=str(BASE_DIR / 'api' / 'key' / 'payment.skey'))
VKEY_PATH = env('VKEY_PATH', default=str(BASE_DIR / 'api' / 'key' / 'payment.vkey'))
SECRET_KEY = env('DJANGO_SECRET_KEY')
ENVIRONMENT = env('ENVIRONMENT')

# Per-network configuration. KOIOS_URL is the JSON-RPC ogmios endpoint we
# POST evaluateTransaction to. Defaults match Koios's public hosting for
# preprod/mainnet; override for self-hosted Koios or alternate networks
# (preview, sanchonet, ...).
ENVIRONMENTS = {
    'preprod': {
        'NETWORK': env('PREPROD_NETWORK'),
        'TXID': env('PREPROD_TXID'),
        'TXIDX': env.int('PREPROD_TXIDX'),
        'KOIOS_URL': env('PREPROD_KOIOS_URL', default='https://preprod.koios.rest/api/v1/ogmios'),
    },
    'mainnet': {
        'NETWORK': env('MAINNET_NETWORK'),
        'TXID': env('MAINNET_TXID'),
        'TXIDX': env.int('MAINNET_TXIDX'),
        'KOIOS_URL': env('MAINNET_KOIOS_URL', default='https://api.koios.rest/api/v1/ogmios'),
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
COLLATERAL_THROTTLE_RATE = env('COLLATERAL_THROTTLE_RATE', default='60/min')

# X-Forwarded-For is only trusted when the immediate connection (i.e. the
# REMOTE_ADDR Django sees) is one of these IPs. Defaults to localhost,
# which is right when nginx/Caddy lives on the same host. Multi-host
# deploys should list every load-balancer / reverse-proxy egress IP.
# An empty list disables XFF trust entirely.
TRUSTED_PROXY_IPS = env.list('TRUSTED_PROXY_IPS', default=['127.0.0.1', '::1'])

# Operator-curated data files. The service reads them on every request
# but only re-parses when the file's mtime advances. Default locations
# put them next to the project (gitignored) so editing + atomic-rename
# is the operator workflow.
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
    # auth + contenttypes are required because DRF imports User lazily for
    # its default permission classes; we don't ship our own user system.
    'django.contrib.auth',
    'django.contrib.contenttypes',
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
    'django.middleware.security.SecurityMiddleware',
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
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Cardano Collateral Provider API',
    'DESCRIPTION': (
        'Submit a Cardano transaction CBOR. If the transaction satisfies the '
        'collateral-usage contract (uses this provider\'s collateral UTxO, '
        'requires this provider\'s PKH as a signer, does not spend the '
        'collateral, has is_valid=true, and would succeed on-chain), the '
        'service returns a vkey witness CBOR you can attach to the witness set.'
    ),
    'VERSION': API_VERSION,
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
}

CORS_ALLOW_ALL_ORIGINS = True

# Logging. LOG_LEVEL controls the api logger; LOG_FILE is where we write
# (rotated at 1 MiB x 3 backups). LOG_FORMAT picks plain text (default) or
# JSON-per-line (for log-aggregator ingest). Defaults preserve existing
# behavior so existing logrotate / monitoring keep working.
LOG_LEVEL = env('LOG_LEVEL', default='DEBUG')
LOG_FILE = env('LOG_FILE', default=str(BASE_DIR / 'debug.log'))
LOG_FORMAT = env('LOG_FORMAT', default='text')  # 'text' or 'json'
if LOG_FORMAT not in ('text', 'json'):
    raise RuntimeError(f"LOG_FORMAT must be 'text' or 'json', got {LOG_FORMAT!r}")

# Every record gets a request_id field via the RequestIDLogFilter, which
# reads from a contextvar set by RequestIDMiddleware. Outside a request
# (startup, management commands) the id is "-".
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'request_id': {
            '()': 'api.middleware.RequestIDLogFilter',
        },
    },
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} [{request_id}] {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} [{request_id}] {message}',
            'style': '{',
        },
        'json': {
            '()': 'api.log_format.JsonFormatter',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'json' if LOG_FORMAT == 'json' else 'simple',
            'filters': ['request_id'],
        },
        'file': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOG_FILE,
            'formatter': 'json' if LOG_FORMAT == 'json' else 'verbose',
            'filters': ['request_id'],
            'maxBytes': 1024 * 1024 * 1,
            'backupCount': 3,
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'api': {
            'handlers': ['file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'django.security.DisallowedHost': {
            'handlers': ['file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

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
