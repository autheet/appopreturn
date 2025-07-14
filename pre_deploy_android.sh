#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.
set -x # Enable debug output

# --- Configuration ---
MAIN_BRANCH_NAME="main"
FIREBASE_ANDROID_APP_ID="1:1706363000:android:ec92a8ef9867c44ce1858d" # From your google-services.json via firebase_options.dart

# --- Store Current Branch ---
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Currently on branch: $CURRENT_BRANCH"

# --- Fetch latest changes from remote for all branches and tags ---
echo "Fetching latest from remote..."
git fetch --all --tags

# --- Determine Build Name and Build Number ---
echo "Determining build name and number..."
BUILD_NAME=$(git describe --tags --abbrev=0 origin/$MAIN_BRANCH_NAME 2>/dev/null)
if [ -z "$BUILD_NAME" ]; then
  echo "No Git tags found on 'origin/$MAIN_BRANCH_NAME'. Using default build name '1.0.0'."
  BUILD_NAME="1.0.0"
else
  BUILD_NAME=${BUILD_NAME#v}
  echo "Using build name from Git tag on 'origin/$MAIN_BRANCH_NAME': $BUILD_NAME"
fi

BUILD_NUMBER=$(git rev-list --count origin/$MAIN_BRANCH_NAME)
if [ -z "$BUILD_NUMBER" ]; then
  echo "Could not determine commit count for 'origin/$MAIN_BRANCH_NAME'. Using default build number '1'."
  BUILD_NUMBER="1"
else
  echo "Using build number from commit count on 'origin/$MAIN_BRANCH_NAME': $BUILD_NUMBER"
fi
# --- End of Determining Build Name and Build Number ---

# --- Build Flutter Android App (App Bundle) ---
echo "Building Flutter Android app bundle with dynamic build name and number..."
echo "Android Build Name: $BUILD_NAME"
echo "Android Build Number: $BUILD_NUMBER"

DEBUG_SYMBOL_PATH_ANDROID="build/android_app_symbols"
mkdir -p "$DEBUG_SYMBOL_PATH_ANDROID"

flutter build appbundle --release \
  --build-name="$BUILD_NAME" \
  --build-number="$BUILD_NUMBER" \
  --obfuscate \
  --split-debug-info="$DEBUG_SYMBOL_PATH_ANDROID"

echo "Flutter Android app bundle built successfully."
echo "Android App Bundle typically located at: build/app/outputs/bundle/release/app-release.aab" # Path might vary with custom buildDir
echo "Debug symbols for Android are in $DEBUG_SYMBOL_PATH_ANDROID"
# --- End of Flutter Android App Build ---

# --- Upload Android Debug Symbols to Firebase Crashlytics ---
#echo "Uploading Android debug symbols to Firebase Crashlytics..."
#if [ -d "$DEBUG_SYMBOL_PATH_ANDROID" ] && [ "$(ls -A $DEBUG_SYMBOL_PATH_ANDROID)" ]; then
#  # The command expects the path to the directory containing the .symbols files
#  firebase crashlytics:symbols:upload --app="$FIREBASE_ANDROID_APP_ID" "$DEBUG_SYMBOL_PATH_ANDROID"
#  echo "Android debug symbols upload attempt finished."
#else
#  echo "Warning: Debug symbols directory '$DEBUG_SYMBOL_PATH_ANDROID' is empty or does not exist. Skipping upload."
#fi
# --- End of Uploading Debug Symbols ---

echo "Pre-deploy script for Android finished."
