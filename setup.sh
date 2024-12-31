#!/bin/bash

# Check for Python3 and validate version
if ! command -v python3.10 &>/dev/null && ! command -v python3.11 &>/dev/null && ! command -v python3.12 &>/dev/null; then
    echo '[ERROR] Python 3.10-3.12 is required but not installed.' >&2
    exit 1
fi
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "[INSTALL] Found Python ${python_version}"

# Check and upgrade pip
if python3 -m pip -V &>/dev/null; then
    echo '[INSTALL] Found pip'
    python3 -m pip install --no-cache-dir --upgrade pip
else
    echo '[ERROR] python3-pip not installed'
    exit 1
fi

# Install Poetry
if ! command -v poetry &>/dev/null; then
    echo '[INSTALL] Installing Poetry'
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
fi

# macOS-specific Xcode CLI tools check
if [[ "$(uname)" == "Darwin" ]]; then
    if ! xcode-select -v &>/dev/null; then
        echo 'Please install command-line tools with: xcode-select --install'
        exit 1
    fi
    echo '[INSTALL] Found Xcode'
fi

# Install dependencies and set up the environment
echo '[INSTALL] Installing Requirements'
poetry lock
poetry install --no-root --only main --no-interaction --no-ansi

# Clean script execution
if [[ -f scripts/clean.sh ]]; then
    bash scripts/clean.sh y
else
    echo '[WARNING] clean.sh script not found, skipping clean-up.'
fi

# Database setup and superuser creation
echo '[INSTALL] Migrating Database'
export DJANGO_SUPERUSER_USERNAME=root
export DJANGO_SUPERUSER_PASSWORD=root

poetry run python manage.py makemigrations || exit 1
poetry run python manage.py makemigrations Static_Analyzer || exit 1
poetry run python manage.py migrate || exit 1
poetry run python manage.py createsuperuser --noinput --email "" || \
    echo '[WARNING] Failed to create superuser. Please create manually.'
poetry run python manage.py create_roles

# Check for wkhtmltopdf
if ! command -v wkhtmltopdf &>/dev/null; then
    echo 'Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html'
fi

# Final check and summary
echo '[INSTALL] Checking Installation'
poetry run python manage.py check || echo '[WARNING] Django project checks failed.'
echo '[INSTALL] Installation Complete'
