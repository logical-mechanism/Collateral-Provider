import os
import sys
from pathlib import Path

import environ

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

# Add your variables here
PKH = env('PKH')
SKEY_PATH = os.path.join(BASE_DIR, 'api/key/payment.skey')
VKEY_PATH = os.path.join(BASE_DIR, 'api/key/payment.vkey')
SECRET_KEY = env('DJANGO_SECRET_KEY')
ENVIRONMENT = env('ENVIRONMENT')

# uncomment the networks being used
ENVIRONMENTS = {
    'preprod': {
        'NETWORK': env("PREPROD_NETWORK"),
        'TXID': env('PREPROD_TXID'),
        'TXIDX': env.int('PREPROD_TXIDX'),
    },
    'mainnet': {
        'NETWORK': env("MAINNET_NETWORK"),
        'TXID': env('MAINNET_TXID'),
        'TXIDX': env.int('MAINNET_TXIDX'),
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

INSTALLED_APPS = [
    # auth + contenttypes are required because DRF imports User lazily for
    # its default permission classes; we don't ship our own user system.
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'api',
]

# We don't use sessions, auth, or CSRF — this is a stateless public POST API.
# Skip the corresponding middleware so each request doesn't pay for them.
# Disallowed-host responses are formatted by handler400 in urls.py; we rely
# on Django's built-in ALLOWED_HOSTS check rather than a custom middleware.
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # must precede CommonMiddleware
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

REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        # keep this at 1 as the worst case fallback
        'anon': '1/min',
    }
}

CORS_ALLOW_ALL_ORIGINS = True

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'debug.log'),
            'formatter': 'verbose',
            'maxBytes': 1024 * 1024 * 1,
            'backupCount': 3,
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'api': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'django.security.DisallowedHost': {
            'handlers': ['file'],
            'level': 'WARNING',  # Reduce the log level to WARNING
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
