# noqa: E800
"""
Django settings for VulnHawk project.

VulnHawk and Django settings
"""

import logging
import os

from vulnhawk.VulnHawk.init import (
    first_run,
    get_vulnhawk_home,
    get_vulnhawk_version,
    get_secret_from_file_or_env,
    load_source,
)

logger = logging.getLogger(__name__)
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       VULNHawk CONFIGURATION
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
BANNER, VERSION, VULNHAWK_VER = get_vulnhawk_version()
USE_HOME = True
# True : All Uploads/Downloads will be stored in user's home directory
# False : All Uploads/Downloads will be stored under VulnHawk root directory

# VulnHawk Data Directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULNHawk_HOME = get_vulnhawk_home(USE_HOME, BASE_DIR)
# Download Directory
DWD_DIR = os.path.join(VULNHawk_HOME, 'downloads/')
# Screenshot Directory
SCREEN_DIR = os.path.join(VULNHawk_HOME, 'downloads/screen/')
# Upload Directory
UPLD_DIR = os.path.join(VULNHawk_HOME, 'uploads/')
# Database Directory
DB_DIR = os.path.join(VULNHawk_HOME, 'db.sqlite3')
# Signatures used by modules
SIGNATURE_DIR = os.path.join(VULNHawk_HOME, 'signatures/')
# Tools Directory
TOOLS_DIR = os.path.join(BASE_DIR, 'Dynamic_Analyzer/tools/')
# Downloaded Tools Directory
DOWNLOADED_TOOLS_DIR = os.path.join(VULNHawk_HOME, 'tools/')
# Secret File
SECRET_FILE = os.path.join(VULNHawk_HOME, 'secret')

# ==========Load VulnHawk User Settings==========
try:
    if USE_HOME:
        USER_CONFIG = os.path.join(VULNHawk_HOME, 'config.py')
        sett = load_source('user_settings', USER_CONFIG)
        locals().update(  # lgtm [py/modification-of-locals]
            {k: v for k, v in list(sett.__dict__.items())
                if not k.startswith('__')})
        CONFIG_HOME = True
    else:
        CONFIG_HOME = False
except Exception:
    logger.exception('Reading Config')
    CONFIG_HOME = False

# ===VULNHawk SECRET GENERATION AND DB MIGRATION====
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR, VULNHawk_HOME)

# =============ALLOWED DOWNLOAD EXTENSIONS=====
ALLOWED_EXTENSIONS = {
    '.txt': 'text/plain',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp',
    '.zip': 'application/zip',
    '.tar': 'application/x-tar',
    '.apk': 'application/octet-stream',
    '.apks': 'application/octet-stream',
    '.xapk': 'application/octet-stream',
    '.aab': 'application/octet-stream',
    '.ipa': 'application/octet-stream',
    '.jar': 'application/java-archive',
    '.aar': 'application/octet-stream',
    '.so': 'application/octet-stream',
    '.dylib': 'application/octet-stream',
    '.a': 'application/octet-stream',
    '.pcap': 'application/vnd.tcpdump.pcap',
    '.appx': 'application/vns.ms-appx',
}
# =============ALLOWED MIMETYPES=================
APK_MIME = [
    'application/octet-stream',
    'application/vnd.android.package-archive',
    'application/x-zip-compressed',
    'binary/octet-stream',
    'application/java-archive',
    'application/x-authorware-bin',
]
IPA_MIME = [
    'application/iphone',
    'application/octet-stream',
    'application/x-itunes-ipa',
    'application/x-zip-compressed',
    'application/x-ar',
    'text/vnd.a',
    'binary/octet-stream',
]
ZIP_MIME = [
    'application/zip',
    'application/octet-stream',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
APPX_MIME = [
    'application/octet-stream',
    'application/vns.ms-appx',
    'application/x-zip-compressed',
]
# Supported File Extensions
ANDROID_EXTS = (
    'apk', 'xapk', 'apks', 'zip',
    'aab', 'so', 'jar', 'aar',
)
IOS_EXTS = ('ipa', 'dylib', 'a')
WINDOWS_EXTS = ('appx',)
# REST API only mode
# Set VULNHawk_API_ONLY to 1 to enable REST API only mode
# In this mode, web UI related urls are disabled.
API_ONLY = os.getenv('VULNHawk_API_ONLY', '0')

# -----External URLS--------------------------
MALWARE_DB_URL = 'https://www.malwaredomainlist.com/mdlcsv.php'
MALTRAIL_DB_URL = ('https://raw.githubusercontent.com/stamparm/aux/'
                   'master/maltrail-malware-domains.txt')
VIRUS_TOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/'
EXODUS_URL = 'https://reports.exodus-privacy.eu.org'
APPMONSTA_URL = 'https://api.appmonsta.com/v1/stores/android/details/'
ITUNES_URL = 'https://itunes.apple.com/lookup'
GITHUB_URL = ('https://github.com/VulnHawk/VulnHawk-AndroidAppSec-Frameworkk-VulnHawk/'
              'releases/latest')
FRIDA_SERVER = 'https://api.github.com/repos/frida/frida/releases/tags/'
GOOGLE = 'https://www.google.com'
BAIDU = 'https://www.baidu.com/'
APKPURE = 'https://m.apkpure.com/android/{}/download?from=details'
APKTADA = 'https://apktada.com/download-apk/'
APKPLZ = 'https://apkplz.net/download-app/'

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ============DJANGO SETTINGS =================
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
if (os.environ.get('POSTGRES_USER')
        and (os.environ.get('POSTGRES_PASSWORD')
             or os.environ.get('POSTGRES_PASSWORD_FILE'))
        and os.environ.get('POSTGRES_HOST')):
    # Postgres support
    default = {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.getenv('POSTGRES_DB', 'vulnhawk'),
        'USER': os.environ['POSTGRES_USER'],
        'PASSWORD': get_secret_from_file_or_env('POSTGRES_PASSWORD'),
        'HOST': os.environ['POSTGRES_HOST'],
        'PORT': int(os.getenv('POSTGRES_PORT', 5432)),
    }
else:
    # Sqlite3 support
    default = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_DIR,
    }
DATABASES = {
    'default': default,
}
# ===============================================
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
DEBUG = bool(os.getenv('VULNHawk_DEBUG', '0') == '1')
DJANGO_LOG_LEVEL = DEBUG
TEMPLATE_DEBUG = DEBUG
ALLOWED_HOSTS = ['127.0.0.1', 'vulnhawk', '*']
# Application definition
INSTALLED_APPS = (
    # 'django.contrib.admin',
    'django_q',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'vulnhawk.Static_Analyzer',
    'vulnhawk.Dynamic_Analyzer',
    'vulnhawk.Ml_Analyzer',
    'vulnhawk.VulnHawk',
    'vulnhawk.Malware_Analyzer',
)
MIDDLEWARE_CLASSES = (
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_ratelimit.middleware.RatelimitMiddleware',
)
MIDDLEWARE = (
    'vulnhawk.VulnHawk.views.api.api_middleware.RestApiAuthMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)
ROOT_URLCONF = 'vulnhawk.VulnHawk.urls'
WSGI_APPLICATION = 'vulnhawk.VulnHawk.wsgi.application'
LANGUAGE_CODE = 'en-us'
TIME_ZONE = os.getenv('TIME_ZONE', 'UTC')
USE_I18N = True
USE_L10N = True
USE_TZ = True
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'DIRS':
            [
                os.path.join(BASE_DIR, 'templates'),
            ],
        'OPTIONS':
            {
                'debug': TEMPLATE_DEBUG,
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
    },
]
MEDIA_ROOT = os.path.join(BASE_DIR, 'uploads')
MEDIA_URL = '/uploads/'
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
# 256MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 268435456
LOGIN_URL = 'login'
LOGOUT_REDIRECT_URL = '/'
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': ('django.contrib.auth.password_validation.'
                 'UserAttributeSimilarityValidator'),
    },
    {
        'NAME': ('django.contrib.auth.password_validation.'
                 'MinimumLengthValidator'),
        'OPTIONS': {
            'min_length': 6,
        },
    },
    {
        'NAME': ('django.contrib.auth.password_validation.'
                 'CommonPasswordValidator'),
    },
    {
        'NAME': ('django.contrib.auth.password_validation.'
                 'NumericPasswordValidator'),
    },
]
# Better logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'standard': {
            'format': '[%(levelname)s] %(asctime)-15s - %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
        },
        'color': {
            '()': 'colorlog.ColoredFormatter',
            'format':
                '%(log_color)s[%(levelname)s] %(asctime)-15s - %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
            'log_colors': {
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        },
    },
    'handlers': {
        'logfile': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(VULNHawk_HOME, 'debug.log'),
            'formatter': 'standard',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'color',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django_q': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['console', 'logfile'],
            # DEBUG will log all queries, so change it to WARNING.
            'level': 'INFO',
            'propagate': False,   # Don't propagate to other handlers
        },
        'vulnhawk.VulnHawk': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'vulnhawk.Static_Analyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'vulnhawk.Malware_Analyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'vulnhawk.Dynamic_Analyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
ASYNC_ANALYSIS = bool(os.getenv('VULNHawk_ASYNC_ANALYSIS', '0') == '1')
ASYNC_ANALYSIS_TIMEOUT = int(os.getenv('VULNHawk_ASYNC_ANALYSIS_TIMEOUT', '60'))
Q_CLUSTER = {
    'name': 'scan_queue',
    'workers': int(os.getenv('VULNHawk_ASYNC_WORKERS', 3)),
    'recycle': 5,
    'timeout': ASYNC_ANALYSIS_TIMEOUT * 60,
    'retry': (ASYNC_ANALYSIS_TIMEOUT * 60) + 100,
    'compress': True,
    'label': 'scan_queue',
    'orm': 'default',
    'max_attempts': 1,
    'save_limit': -1,
    'ack_failures': True,
}
QUEUE_MAX_SIZE = 100
MULTIPROCESSING = os.getenv('VULNHawk_MULTIPROCESSING')
JADX_TIMEOUT = int(os.getenv('VULNHawk_JADX_TIMEOUT', 1000))
SAST_TIMEOUT = int(os.getenv('VULNHawk_SAST_TIMEOUT', 1000))
BINARY_ANALYSIS_TIMEOUT = int(os.getenv('VULNHawk_BINARY_ANALYSIS_TIMEOUT', 600))
DISABLE_AUTHENTICATION = os.getenv('VULNHawk_DISABLE_AUTHENTICATION')
RATELIMIT = os.getenv('VULNHawk_RATELIMIT', '7/m')
USE_X_FORWARDED_HOST = bool(
    os.getenv('VULNHawk_USE_X_FORWARDED_HOST', '1') == '1')
USE_X_FORWARDED_PORT = bool(
    os.getenv('VULNHawk_USE_X_FORWARDED_PORT', '1') == '1')
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# ===========================
# ENTERPRISE FEATURE REQUESTS
# ===========================
EFR_01 = os.getenv('EFR_01', '0')
# SAML SSO
# IdP Configuration
IDP_METADATA_URL = os.getenv('VULNHawk_IDP_METADATA_URL')
IDP_ENTITY_ID = os.getenv('VULNHawk_IDP_ENTITY_ID')
IDP_SSO_URL = os.getenv('VULNHawk_IDP_SSO_URL')
IDP_X509CERT = os.getenv('VULNHawk_IDP_X509CERT')
IDP_IS_ADFS = os.getenv('VULNHawk_IDP_IS_ADFS', '0')
# SP Configuration
SP_HOST = os.getenv('VULNHawk_SP_HOST')
SP_ALLOW_PASSWORD = os.getenv('VULNHawk_SP_ALLOW_PASSWORD', '0')
# ===================
# USER CONFIGURATION
# ===================
if CONFIG_HOME:
    logger.info('Loading User config from: %s', USER_CONFIG)
else:
    """
    IMPORTANT
    If 'USE_HOME' is set to True,
    then below user configuration settings are not considered.
    The user configuration will be loaded from
    .VulnHawk/config.py in user's home directory.
    """
    # ^CONFIG-START^: Do not edit this line
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #          VULNHawk USER CONFIGURATIONS
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # -------------------------
    # STATIC ANALYZER SETTINGS
    # -------------------------

    # ==========ANDROID SKIP CLASSES==========================
    # Common third party classes/paths that will be skipped
    # during static analysis
    import os
    SKIP_CLASS_PATH = {
        'com/google/', 'androidx', 'okhttp2/', 'okhttp3/',
        'com/android/', 'com/squareup', 'okhttp/'
        'android/content/', 'com/twitter/', 'twitter4j/',
        'android/support/', 'org/apache/', 'oauth/signpost',
        'android/arch', 'org/chromium/', 'com/facebook',
        'org/spongycastle', 'org/bouncycastle',
        'com/amazon/identity/', 'io/fabric/sdk',
        'com/instabug', 'com/crashlytics/android',
        'kotlinx/', 'kotlin/',
    }
    # Disable CVSSV2 Score by default
    CVSS_SCORE_ENABLED = bool(os.getenv('VULNHawk_CVSS_SCORE_ENABLED', ''))
    # NIAP Scan
    NIAP_ENABLED = os.getenv('VULNHawk_NIAP_ENABLED', '')
    # Permission to Code Mapping
    PERM_MAPPING_ENABLED = os.getenv('VULNHawk_PERM_MAPPING_ENABLED', '1')
    # Dex 2 Smali Conversion
    DEX2SMALI_ENABLED = os.getenv('VULNHawk_DEX2SMALI_ENABLED', '1')
    # Android Shared Object Binary Analysis
    SO_ANALYSIS_ENABLED = os.getenv('VULNHawk_SO_ANALYSIS_ENABLED', '1')
    # iOS Dynamic Library Binary Analysis
    DYLIB_ANALYSIS_ENABLED = os.getenv('VULNHawk_DYLIB_ANALYSIS_ENABLED', '1')
    # =================================================
    # --------------------------
    # MALWARE ANALYZER SETTINGS
    # --------------------------

    DOMAIN_MALWARE_SCAN = os.getenv('VULNHawk_DOMAIN_MALWARE_SCAN', '1')
    APKID_ENABLED = os.getenv('VULNHawk_APKID_ENABLED', '1')
    # ==================================================
    # ======WINDOWS STATIC ANALYSIS SETTINGS ===========
    # Private key
    WINDOWS_VM_SECRET = os.getenv(
        'VULNHawk_WINDOWS_VM_SECRET', 'vulnhawk/VulnHawk/windows_vm_priv_key.asc')
    # IP and Port of the VulnHawk Windows VM
    # example: WINDOWS_VM_IP = '127.0.0.1'   ;noqa E800
    WINDOWS_VM_IP = os.getenv('VULNHawk_WINDOWS_VM_IP')
    WINDOWS_VM_PORT = os.getenv('VULNHawk_WINDOWS_VM_PORT', '8000')
    # ==================================================

    # ==============3rd Party Tools=====================
    """
    If you want to use a different version of 3rd party tools used by VulnHawk.
    You can do that by specifying the path here. If specified, VulnHawk will run
    the tool from this location.
    """

    # Android 3P Tools
    BUNDLE_TOOL = os.getenv('VULNHawk_BUNDLE_TOOL', '')
    JADX_BINARY = os.getenv('VULNHawk_JADX_BINARY', '')
    BACKSMALI_BINARY = os.getenv('VULNHawk_BACKSMALI_BINARY', '')
    VD2SVG_BINARY = os.getenv('VULNHawk_VD2SVG_BINARY', '')
    APKTOOL_BINARY = os.getenv('VULNHawk_APKTOOL_BINARY', '')
    ADB_BINARY = os.getenv('VULNHawk_ADB_BINARY', '')
    AAPT2_BINARY = os.getenv('VULNHawk_AAPT2_BINARY', '')
    AAPT_BINARY = os.getenv('VULNHawk_AAPT_BINARY', '')

    # iOS 3P Tools
    JTOOL_BINARY = os.getenv('VULNHawk_JTOOL_BINARY', '')
    CLASSDUMP_BINARY = os.getenv('VULNHawk_CLASSDUMP_BINARY', '')
    CLASSDUMP_SWIFT_BINARY = os.getenv('VULNHawk_CLASSDUMP_SWIFT_BINARY', '')

    # COMMON
    JAVA_DIRECTORY = os.getenv('VULNHawk_JAVA_DIRECTORY', '')

    """
    Examples:
    JAVA_DIRECTORY = 'C:/Program Files/Java/jdk1.7.0_17/bin/'
    JAVA_DIRECTORY = '/usr/bin/'
    JADX_BINARY = 'C:/Users/Ajin/AppData/Local/Programs/jadx/bin/jadx.bat'
    JADX_BINARY = '/Users/ajin/jadx/bin/jadx'
    """
    # ==========================================================
    # -------------------------
    # DYNAMIC ANALYZER SETTINGS
    # -------------------------

    # =======ANDROID DYNAMIC ANALYSIS SETTINGS===========
    ANALYZER_IDENTIFIER = os.getenv('VULNHawk_ANALYZER_IDENTIFIER', '')
    FRIDA_TIMEOUT = int(os.getenv('VULNHawk_FRIDA_TIMEOUT', '4'))
    ACTIVITY_TESTER_SLEEP = int(os.getenv('VULNHawk_ACTIVITY_TESTER_SLEEP', '4'))
    # ==============================================

    # ================HTTPS PROXY ===============
    PROXY_IP = os.getenv('VULNHawk_PROXY_IP', '127.0.0.1')
    PROXY_PORT = int(os.getenv('VULNHawk_PROXY_PORT', '1337'))
    # ===================================================

    # ========UPSTREAM PROXY SETTINGS ==============
    # If you are behind a Proxy
    UPSTREAM_PROXY_ENABLED = bool(os.getenv(
        'VULNHawk_UPSTREAM_PROXY_ENABLED', ''))
    UPSTREAM_PROXY_SSL_VERIFY = os.getenv(
        'VULNHawk_UPSTREAM_PROXY_SSL_VERIFY', '1')
    UPSTREAM_PROXY_TYPE = os.getenv('VULNHawk_UPSTREAM_PROXY_TYPE', 'http')
    UPSTREAM_PROXY_IP = os.getenv('VULNHawk_UPSTREAM_PROXY_IP', '127.0.0.1')
    UPSTREAM_PROXY_PORT = int(os.getenv('VULNHawk_UPSTREAM_PROXY_PORT', '3128'))
    UPSTREAM_PROXY_USERNAME = os.getenv('VULNHawk_UPSTREAM_PROXY_USERNAME', '')
    UPSTREAM_PROXY_PASSWORD = os.getenv('VULNHawk_UPSTREAM_PROXY_PASSWORD', '')
    # ==============================================

    # ========DISABLED BY DEFAULT COMPONENTS=========
    # Get AppMonsta API from https://appmonsta.com/dashboard/get_api_key/
    APPMONSTA_API = os.getenv('VULNHawk_APPMONSTA_API', '')
    # ----------VirusTotal--------------------------
    VT_ENABLED = bool(os.getenv('VULNHawk_VT_ENABLED', ''))
    VT_API_KEY = os.getenv('VULNHawk_VT_API_KEY', '')
    VT_UPLOAD = bool(os.getenv('VULNHawk_VT_UPLOAD', ''))
    # Before setting VT_ENABLED to True,
    # Make sure VT_API_KEY is set to your VirusTotal API key
    # register at: https://www.virustotal.com/#/join-us
    # You can get your API KEY from:
    # https://www.virustotal.com/en/user/<username>/apikey/
    # Files will be uploaded to VirusTotal
    # if VT_UPLOAD is set to True.
    # ===============================================
    # =======IOS DYNAMIC ANALYSIS SETTINGS===========
    CORELLIUM_API_DOMAIN = os.getenv('VULNHawk_CORELLIUM_API_DOMAIN', '')
    CORELLIUM_API_KEY = os.getenv('VULNHawk_CORELLIUM_API_KEY', '')
    CORELLIUM_PROJECT_ID = os.getenv('VULNHawk_CORELLIUM_PROJECT_ID', '')
    # CORELLIUM_PROJECT_ID is optional, VulnHawk will use any available project id
    # ===============================================
    # ^CONFIG-END^: Do not edit this line
