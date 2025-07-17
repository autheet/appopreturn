#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

firebase login
firebase init

flutterfire configure

dart run flutter_launcher_icons:main
dart run flutter_native_splash:create

# firebase functions:secrets:set WALLET_PRIVATE_KEY
# get fingerprints:
gradlew signingReport
# keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
# keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
# keytool -list -v -keystore "android/upload-keystore-appopreturn.jks" -alias upload -storepass android -keypass android
