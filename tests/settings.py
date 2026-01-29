import django


ADMINS = ()

MANAGERS = ADMINS

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

AUTH_USER_MODEL = "auth.User"
OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2_provider.Application"
OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL = "oauth2_provider.AccessToken"
OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL = "oauth2_provider.RefreshToken"

ALLOWED_HOSTS = []

TIME_ZONE = "UTC"

LANGUAGE_CODE = "en-us"

SITE_ID = 1

USE_I18N = True
if django.VERSION < (4, 0):
    USE_L10N = True
USE_TZ = True

MEDIA_ROOT = ""
MEDIA_URL = ""

STATIC_ROOT = ""
STATIC_URL = "/static/"

STATICFILES_DIRS = ()

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

# Make this unique, and don"t share it with anybody.
SECRET_KEY = "1234567890jazzband"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": True,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.request",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
)

ROOT_URLCONF = "tests.urls"

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "django.contrib.messages",
    "oauth2_provider",
    "tests",
)

PASSWORD_HASHERS = django.conf.settings.PASSWORD_HASHERS + ["tests.custom_hasher.MyPBKDF2PasswordHasher"]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {"format": "%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s"},
        "simple": {"format": "%(levelname)s %(message)s"},
    },
    "filters": {"require_debug_false": {"()": "django.utils.log.RequireDebugFalse"}},
    "handlers": {
        "mail_admins": {
            "level": "ERROR",
            "filters": ["require_debug_false"],
            "class": "django.utils.log.AdminEmailHandler",
        },
        "console": {"level": "DEBUG", "class": "logging.StreamHandler", "formatter": "simple"},
        "null": {
            "level": "DEBUG",
            "class": "logging.NullHandler",
        },
    },
    "loggers": {
        "django.request": {
            "handlers": ["mail_admins"],
            "level": "ERROR",
            "propagate": True,
        },
        "oauth2_provider": {
            "handlers": ["null"],
            "level": "DEBUG",
            "propagate": True,
        },
    },
}

OIDC_RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCbCYh5h2NmQuBqVO6G+/CO+cHm9VBzsb0MeA6bbQfDnbhstVOT
j0hcnZJzDjYc6ajBZZf6gxVP9xrdm9Uh599VI3X5PFXLbMHrmzTAMzCGIyg+/fnP
0gocYxmCX2+XKyj/Zvt1pUX8VAN2AhrJSfxNDKUHERTVEV9bRBJg4F0C3wIDAQAB
AoGAP+i4nNw+Ec/8oWh8YSFm4xE6qKG0NdTtSMAOyWwy+KTB+vHuT1QPsLn1vj77
+IQrX/moogg6F1oV9YdA3vat3U7rwt1sBGsRrLhA+Spp9WEQtglguNo4+QfVo2ju
YBa2rG+h75qjiA3xnU//F3rvwnAsOWv0NUVdVeguyR+u6okCQQDBUmgWeH2WHmUn
2nLNCz+9wj28rqhfOr9Ptem2gqk+ywJmuIr4Y5S1OdavOr2UZxOcEwncJ/MLVYQq
MH+x4V5HAkEAzU2GMR5OdVLcxfVTjzuIC76paoHVWnLibd1cdANpPmE6SM+pf5el
fVSwuH9Fmlizu8GiPCxbJUoXB/J1tGEKqQJBALhClEU+qOzpoZ6/voYi/6kdN3zc
uEy0EN6n09AKb8gS9QH1STgAqh+ltjMkeMe3C2DKYK5/QU9/Pc58lWl1FkcCQG67
ZamQgxjcvJ85FvymS1aqW45KwNysIlzHjFo2jMlMf7dN6kobbPMQftDENLJvLWIT
qoFyGycdsxZiPAIyZSECQQCZFn3Dl6hnJxWZH8Fsa9hj79kZ/WVkIXGmtdgt0fNr
dTnvCVtA59ne4LEVie/PMH/odQWY0SxVm/76uBZv/1vY
-----END RSA PRIVATE KEY-----"""

OIDC_RSA_PRIVATE_KEYS_INACTIVE = [
    """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDSpXNtxaD9+DKBnSWJNoV6h0PZuSKeGPyA8n0/as/O+oboiYj1
gqQSTwPFxzt5Zy52fDmIQvzDH+2CihpGIeJh9SsUEFd8DXkP/Xk91f/mAbytBsnt
czFCtihFRxWbbBAMHh8i5HuxM+rH2nw5Hh/74GLE58zk5rtIRS1DyS+uUQIDAQAB
AoGAca57Ci4TQZ02XL8bp9610Le5hYIlzZ78fvbfY19YwYJxVoQLVzxnIb5k8dMh
JNbru2Q1hHVqhj/v5Xh0z46v5mTOeyQj8F1O6NCkzHtCfF029j8A9+pfNqyQhCa/
nJqsNShFW+uhK67d7QfqtRRR6B30XsIHgND7QJuc14mDkdUCQQD3OpzLZugdTtuW
u+DdrdSjMBbW2p1+NFr8T20Rv+LoMvweZLSuMelAoog8fNxF6xQs7wLw+Tf5z56L
mptnur6TAkEA2h6WL3ippJ6/7H45suxP1dJI+Qal7V2KAMVGbv6Jal9rcKid0PpD
K1uPZwx2o/hkdobPY0HRIFaxpOtwC4FKCwJAYTmWodMFY0k4yA14wBT1c3uc77+n
ghM62NCvdvR8Wo56YcV+3KZaMYX5h7getAxfsdAI2xVXMxG4KvSROvjQqwJAaZ+W
KrbLr6QQXH1jg3lbz7ddDvphL2i0g1sEmIs6EADVDmEYyzHlhQF5l/U5Hn4SaDMw
Cmi81GQm8i3wvCGHsQJBAJC2VVcZ4VIehr3nAbI46w6cXGP6lpBbwT2FxSydRHqz
wfGZQ+qAAThGg3OInQNMqItypEEo3oZhKKvjD1N/iTw=
-----END RSA PRIVATE KEY-----"""
]

OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL = "oauth2_provider.AccessToken"
OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2_provider.Application"
OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL = "oauth2_provider.RefreshToken"
OAUTH2_PROVIDER_ID_TOKEN_MODEL = "oauth2_provider.IDToken"

CLEAR_EXPIRED_TOKENS_BATCH_SIZE = 1
CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = 0
PKCE_REQUIRED = False
