#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.
set -x # Enable debug output

# --- Environment Variable Loading ---
# Load environment variables from .env file if it exists
if [ -f .env ]; then
  export $(cat .env | sed 's/#.*//g' | xargs)
fi

# Check for the required secret
if [ -z "$RECAPTCHA_ENTERPRISE_SITE_KEY" ]; then
  echo "Error: RECAPTCHA_ENTERPRISE_SITE_KEY is not set in the .env file."
  echo "Please create a .env file and add: RECAPTCHA_ENTERPRISE_SITE_KEY=your_key"
  exit 1
fi
# --- End of Environment Variable Loading ---


# --- Configuration ---
MAIN_BRANCH_NAME="main" # Or "master", or your primary branch name

# --- Store Current Branch and Ensure Clean Working Directory ---
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Currently on branch: $CURRENT_BRANCH"

# --- Fetch latest changes from remote for all branches and tags ---
echo "Fetching latest from remote..."
git fetch --all --tags

# --- Determine Build Name and Build Number ---
echo "Determining build name and number..."

# Build Name from the latest Git tag on the main branch
BUILD_NAME=$(git describe --tags --abbrev=0 origin/$MAIN_BRANCH_NAME 2>/dev/null)
if [ -z "$BUILD_NAME" ]; then
  echo "No Git tags found on 'origin/$MAIN_BRANCH_NAME'. Using default build name '1.0.0'."
  BUILD_NAME="1.0.0"
else
  BUILD_NAME=${BUILD_NAME#v} # Remove 'v' prefix if it exists (e.g. v1.2.3 -> 1.2.3)
  echo "Using build name from Git tag on 'origin/$MAIN_BRANCH_NAME': $BUILD_NAME"
fi

# Build Number from the number of commits on the main branch
BUILD_NUMBER=$(git rev-list --count origin/$MAIN_BRANCH_NAME)
if [ -z "$BUILD_NUMBER" ]; then
  echo "Could not determine commit count for 'origin/$MAIN_BRANCH_NAME'. Using default build number '1'."
  BUILD_NUMBER="1"
else
  echo "Using build number from commit count on 'origin/$MAIN_BRANCH_NAME': $BUILD_NUMBER"
fi
# --- End of Determining Build Name and Build Number ---


# --- Build Flutter Web App ---
echo "Building Flutter web app with dynamic build name and number..."
echo "Build Name: $BUILD_NAME"
echo "Build Number: $BUILD_NUMBER"

DEBUG_SYMBOL_PATH_WEB="build/web/debug_symbols"
mkdir -p $DEBUG_SYMBOL_PATH_WEB

flutter build web --release \
  --build-name="$BUILD_NAME" \
  --build-number="$BUILD_NUMBER" \
  --dart-define=RECAPTCHA_ENTERPRISE_SITE_KEY="$RECAPTCHA_ENTERPRISE_SITE_KEY"

echo "Flutter web app built into build/web."

echo "Pre-deploy script finished."
