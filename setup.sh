#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

flutterfire configure

echo "enter the secret, but without quotes!"
firebase functions:secrets:set WALLET_PRIVATE_KEY

