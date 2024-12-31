"""Initialize on first run."""
import logging
import os
import random
import subprocess
import sys
import shutil
import threading
from hashlib import sha256
from pathlib import Path
from importlib import (
    machinery,
    util,
)

from vulnhawk.VulnHawk.tools_download import install_jadx
from vulnhawk.install.windows.setup import windows_config_local

logger = logging.getLogger(__name__)

VERSION = '1.0.0'  # Replace with your version
BANNER = r"""

 ██▒   █▓ █    ██  ██▓     ███▄    █  ██░ ██  ▄▄▄       █     █░██ ▄█▀
▓██░   █▒ ██  ▓██▒▓██▒     ██ ▀█   █ ▓██░ ██▒▒████▄    ▓█░ █ ░█░██▄█▒ 
 ▓██  █▒░▓██  ▒██░▒██░    ▓██  ▀█ ██▒▒██▀▀██░▒██  ▀█▄  ▒█░ █ ░█▓███▄░ 
  ▒██ █░░▓▓█  ░██░▒██░    ▓██▒  ▐▌██▒░▓█ ░██ ░██▄▄▄▄██ ░█░ █ ░█▓██ █▄ 
   ▒▀█░  ▒▒█████▓ ░██████▒▒██░   ▓██░░▓█▒░██▓ ▓█   ▓██▒░░██▒██▓▒██▒ █▄
   ░ ▐░  ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░   ▒ ▒  ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▓░▒ ▒ ▒ ▒▒ ▓▒
   ░ ░░  ░░▒░ ░ ░ ░ ░ ▒  ░░ ░░   ░ ▒░ ▒ ░▒░ ░  ▒   ▒▒ ░  ▒ ░ ░ ░ ░▒ ▒░
     ░░   ░░░ ░ ░   ░ ░      ░   ░ ░  ░  ░░ ░  ░   ▒     ░   ░ ░ ░░ ░ 
      ░     ░         ░  ░         ░  ░  ░  ░      ░  ░    ░   ░  ░   
     ░                                                                
"""  # ASCII Font: Standard


def first_run(secret_file, base_dir, vulnhawk_home):
    """Run initial setup tasks."""
    base_dir = Path(base_dir)
    vulnhawk_home = Path(vulnhawk_home)
    secret_file = Path(secret_file)
    if os.getenv('VULNHAWK_SECRET_KEY'):
        secret_key = os.environ['VULNHAWK_SECRET_KEY']
    elif secret_file.exists() and secret_file.is_file():
        secret_key = secret_file.read_text().strip()
    else:
        try:
            secret_key = get_random()
            secret_file.write_text(secret_key)
        except IOError:
            raise Exception(f'Secret file generation failed: {secret_file}')
        # Run once
        make_migrations(base_dir)
        migrate(base_dir)
        # Install JADX
        thread = threading.Thread(
            target=install_jadx,
            name='install_jadx',
            args=(vulnhawk_home.as_posix(),))
        thread.start()
        # Windows Setup
        windows_config_local(vulnhawk_home.as_posix())
    return secret_key


def create_user_conf(vulnhawk_home, base_dir):
    try:
        config_path = vulnhawk_home / 'config.py'
        if not config_path.exists():
            sample_conf = base_dir / 'VulnHawk' / 'settings.py'
            dat = sample_conf.read_text().splitlines()
            config = []
            add = False
            for line in dat:
                if '^CONFIG-START^' in line:
                    add = True
                if '^CONFIG-END^' in line:
                    break
                if add:
                    config.append(line.lstrip())
            config.pop(0)
            conf_str = '\n'.join(config)
            config_path.write_text(conf_str)
    except Exception:
        logger.exception('Cannot create config file')


def django_operation(cmds, base_dir):
    """Generic Function for Django operations."""
    manage = base_dir.parent / 'manage.py'
    if not manage.exists() or not manage.is_file():
        # Bail out if manage.py doesn't exist
        return
    args = [sys.executable, manage.as_posix()]
    args.extend(cmds)
    subprocess.call(args)


def make_migrations(base_dir):
    """Create database migrations."""
    try:
        django_operation(['makemigrations'], base_dir)
        django_operation(['makemigrations', 'Static_Analyzer'], base_dir)
    except Exception:
        logger.exception('Cannot Make Migrations')


def migrate(base_dir):
    """Apply database migrations."""
    try:
        django_operation(['migrate'], base_dir)
        django_operation(['migrate', '--run-syncdb'], base_dir)
        django_operation(['create_roles'], base_dir)
    except Exception:
        logger.exception('Cannot Migrate')


def get_random():
    """Generate a random secret key."""
    choice = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return ''.join([random.SystemRandom().choice(choice) for _ in range(50)])


def get_vulnhawk_home(use_home, base_dir):
    """Setup and return the VulnHawk home directory."""
    try:
        base_dir = Path(base_dir)
        vulnhawk_home = ''
        if use_home:
            vulnhawk_home = Path.home() / '.VulnHawk'
            custom_home = os.getenv('VULNHAWK_HOME_DIR')
            if custom_home:
                p = Path(custom_home)
                if p.exists() and p.is_absolute() and p.is_dir():
                    vulnhawk_home = p
            # Create VulnHawk Home Directory
            if not vulnhawk_home.exists():
                vulnhawk_home.mkdir(parents=True, exist_ok=True)
            create_user_conf(vulnhawk_home, base_dir)
        else:
            vulnhawk_home = base_dir
        # Create required directories
        for sub_dir in ['downloads', 'screen', 'uploads', 'tools', 'signatures']:
            (vulnhawk_home / sub_dir).mkdir(parents=True, exist_ok=True)
        return vulnhawk_home.as_posix()
    except Exception:
        logger.exception('Creating VulnHawk Home Directory')


def get_vulnhawk_version():
    """Return the VulnHawk version details."""
    return BANNER, VERSION, f'v{VERSION}'


def load_source(modname, filename):
    """Load a module from a file."""
    loader = machinery.SourceFileLoader(modname, filename)
    spec = util.spec_from_file_location(modname, filename, loader=loader)
    module = util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def get_docker_secret_by_file(secret_key):
    """Retrieve a secret from a file in Docker environment."""
    try:
        secret_path = os.environ.get(secret_key)
        path = Path(secret_path)
        if path.exists() and path.is_file():
            return path.read_text().strip()
    except Exception:
        logger.exception('Cannot read secret from %s', secret_path)
    raise Exception('Cannot read secret from file')


def get_secret_from_file_or_env(env_secret_key):
    """Retrieve a secret from a file or environment variable."""
    docker_secret_key = f'{env_secret_key}_FILE'
    if os.environ.get(docker_secret_key):
        return get_docker_secret_by_file(docker_secret_key)
    else:
        return os.environ[env_secret_key]


def api_key(home_dir):
    """Return the REST API Key."""
    # Retrieve from Docker secrets
    if os.environ.get('VULNHAWK_API_KEY_FILE'):
        logger.info('\nAPI Key read from docker secrets')
        try:
            return get_docker_secret_by_file('VULNHAWK_API_KEY_FILE')
        except Exception:
            logger.exception('Cannot read API Key from docker secrets')
    # Retrieve from environment variable
    if os.environ.get('VULNHAWK_API_KEY'):
        logger.info('\nAPI Key read from environment variable')
        return os.environ['VULNHAWK_API_KEY']
    home_dir = Path(home_dir)
    secret_file = home_dir / 'secret'
    if secret_file.exists() and secret_file.is_file():
        try:
            _api_key = secret_file.read_bytes().strip()
            return sha256(_api_key).hexdigest()
        except Exception:
            logger.exception('Cannot Read API Key')
    return None
