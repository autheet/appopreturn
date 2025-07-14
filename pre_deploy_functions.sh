#!/bin/bash
# pre_deploy_functions.sh

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Environment Setup ---
# Create a Python virtual environment in the root of the functions directory
# if it doesn't already exist.
if [ ! -d "functions/venv" ]; then
  echo "Creating virtual environment for Cloud Functions..."
  python3 -m venv functions/venv
fi

# Activate the virtual environment
source functions/venv/bin/activate

# --- Dependency Installation ---
# Install the required Python packages from the consolidated requirements file.
echo "Installing Python dependencies from functions/requirements.txt..."
pip install --upgrade pip
pip install -r functions/requirements.txt

# --- Completion ---
echo "Python Cloud Functions environment is ready for deployment."
