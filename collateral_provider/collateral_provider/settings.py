import os
from pathlib import Path

import environ

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Initialize environment variables
env = environ.Env()
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# Add your variables here
PKH = env('PKH')
CLI_PATH = os.path.join(BASE_DIR, 'api/bin/cardano-cli')
KEY_PATH = os.path.join(BASE_DIR, 'api/key/payment.skey')
SECRET_KEY = env('SECRET_KEY')
ENVIRONMENT = env('ENVIRONMENT')

ENVIRONMENTS = {
    # 'preview': {
    #     'PROJECT_ID': env('PREVIEW_PROJECT_ID'),
    #     'NETWORK': env("PREVIEW_NETWORK"),
    #     'TXID': env('PREVIEW_TXID'),
    #     'TXIDX': env.int('PREVIEW_TXIDX'),
    # },
    'preprod': {
        'PROJECT_ID': env('PREPROD_PROJECT_ID'),
        'NETWORK': env("PREPROD_NETWORK"),
        'TXID': env('PREPROD_TXID'),
        'TXIDX': env.int('PREPROD_TXIDX'),
    },
    # 'mainnet': {
    #     'PROJECT_ID': env('MAINNET_PROJECT_ID'),
    #     'NETWORK': env("MAINNET_NETWORK"),
    #     'TXID': env('MAINNET_TXID'),
    #     'TXIDX': env.int('MAINNET_TXIDX'),
    # },
}

DEBUG = False

ALLOWED_HOSTS = ['127.0.0.1', 'localhost'] if ENVIRONMENT == "development" else env.list('ALLOWED_HOSTS')

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'rest_framework',
    'corsheaders',
    'api'
]

MIDDLEWARE = [
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
            'maxBytes': 1024 * 1024 * 5,  # 5 MB
            'backupCount': 5,  # Keep 3 backup files
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
    },
}
