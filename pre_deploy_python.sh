#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

python3 -m venv functions/venv
source functions/venv/bin/activate
pip install -r functions/requirements.txt