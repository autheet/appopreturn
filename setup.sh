#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

flutterfire configure

dart run flutter_launcher_icons:main
dart run flutter_native_splash:create

echo "enter the secret, but without quotes!"
firebase functions:secrets:set WALLET_PRIVATE_KEY

