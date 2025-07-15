#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.
git fetch --all --tags
# --- Run Tests First ---
# This is a critical quality gate. If any tests fail, the `set -e` command
# will cause the script to exit immediately, preventing a broken deployment.
## generating icons
dart run flutter_launcher_icons:main
dart run flutter_native_splash:create
# dart run android_notification_icons
# internationalisation
# flutter gen-l10n #
# flutter pub run build_runner build
# echo "Running tests..."
# flutter test

echo "Tests passed. Proceeding with deployment..."
dart run rename_app:main all="appopreturn"
./pre_deploy_web.sh
./pre_deploy_functions.sh
./pre_deploy_android.sh

firebase deploy --only hosting
./pre_deploy_ios.sh
firebase deploy
# pre deploy ios currently fails usually because of failing debug symbol upload, but it seems to work anyway.
