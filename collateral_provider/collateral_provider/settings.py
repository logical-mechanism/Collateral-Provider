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
CLI_PATH = os.path.join(BASE_DIR, 'api/bin/cardano-cli')
KEY_PATH = os.path.join(BASE_DIR, 'api/key/payment.skey')
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

ALLOWED_HOSTS = ['127.0.0.1', 'localhost'] if ENVIRONMENT == "development" else env.list('ALLOWED_HOSTS')

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'api'
]

MIDDLEWARE = [
    'api.middleware.HandleDisallowedHostMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'corsheaders.middleware.CorsMiddleware',
]

ROOT_URLCONF = 'collateral_provider.urls'

WSGI_APPLICATION = 'collateral_provider.wsgi.application'

# TEMPLATES setting to support Django REST Framework's browsable API and any template rendering
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],  # Add custom template directories here
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
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

# Production-specific settings
if ENVIRONMENT == 'production':
    # Enforce HTTPS
    SECURE_SSL_REDIRECT = False

    # HSTS to enforce HTTPS in browsers
    SECURE_HSTS_SECONDS = 0  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

    # If you're not using Django sessions or CSRF, you can skip these
    SESSION_COOKIE_SECURE = False  # Not needed if no session-based authentication
    CSRF_COOKIE_SECURE = False  # No CSRF needed for open API
    CSRF_COOKIE_HTTPONLY = False  # CSRF not required for open API
    CSRF_COOKIE_SAMESITE = None  # Not applicable if CSRF is disabled
else:
    # In development or testing environments
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False


STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # This is your static folder
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
