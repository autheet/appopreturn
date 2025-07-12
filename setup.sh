flutterfire configure
gcloud projects add-iam-policy-binding appopreturn-prod \
    --member="serviceAccount:appopreturn-prod@appspot.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
firebase functions:secrets:set WALLET_PRIVATE_KEY
