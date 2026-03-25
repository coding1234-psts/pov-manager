"""
Test settings for running pytest.
Uses the test_povmanager database.
"""
import os

# Set default environment variables for testing BEFORE importing settings
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-testing-only')
os.environ.setdefault('DATABASE_URL', 'postgres://postgres:postgres@localhost:5432/test_povmanager')
os.environ.setdefault('MONGO_HOST', 'localhost')
os.environ.setdefault('MONGO_PORT', '27017')
os.environ.setdefault('MONGO_USER', 'test')
os.environ.setdefault('MONGO_PASSWORD', 'test')
os.environ.setdefault('MONGO_DB_NAME', 'test_db')
os.environ.setdefault('CLIENT_ID', 'test_client_id')
os.environ.setdefault('CLIENT_SECRET', 'test_client_secret')
os.environ.setdefault('XDR_DEFAULT_REGION', 'test_region')
os.environ.setdefault('VDR_ACCESS_TOKEN', 'test_vdr_token')
os.environ.setdefault('VDR_TEAM_ID', 'test_team_id')
os.environ.setdefault('CTU_ACCESS_TOKEN', 'test_ctu_token')
os.environ.setdefault('CTU_REPORTS_PATH', '/tmp/reports')
os.environ.setdefault('CTU_BASE_URL', 'https://ctu.test.com')

from .settings import *  # noqa: F401, F403

# Override database to use test_povmanager
# This modifies the database name from the main settings
if 'default' in DATABASES:
    # Get the current database config and change the name to test_povmanager
    db_config = DATABASES['default'].copy()
    if 'NAME' in db_config:
        # Replace the database name with test_povmanager
        db_config['NAME'] = 'test_povmanager'
        # Tell Django to use this exact name for tests (no "test_" prefix)
        db_config['TEST'] = {'NAME': 'test_povmanager'}
        DATABASES['default'] = db_config

# Faster password hashing for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Disable logging during tests
LOGGING = {}

# Debug mode for tests
DEBUG = False
