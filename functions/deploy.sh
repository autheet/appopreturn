#!/bin/bash

# This script prepares and deploys the Python Cloud Functions.
# Run this script after cloning the repository or before deploying for the first time.
# It sets up a virtual environment, installs dependencies, and deploys the functions.

# Before running, make sure you are logged into Firebase (firebase login)
# and have selected the correct project (firebase use <project_id>).

# Navigate to the functions directory
cd "$(dirname "$0")"

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Deploy the functions
echo "Deploying functions to Firebase..."
firebase deploy --only functions

# Deactivate the virtual environment
deactivate

echo "Deployment script finished."
