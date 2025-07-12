import os
import hashlib
import sys
import traceback
import logging
import firebase_admin
from dotenv import load_dotenv
from firebase_functions import https_fn, params
from bit import PrivateKeyTestnet
from Crypto.Hash import RIPEMD160
from firebase_functions.params import SecretParam

# --- Initialize Firebase Admin SDK ---
firebase_admin.initialize_app()
# -----------------------------------

# Load environment variables from .env file FOR LOCAL TESTING ONLY
load_dotenv()

# Configure logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# Define the secret parameter
WALLET_PRIVATE_KEY = SecretParam("WALLET_PRIVATE_KEY")

def process_appopreturn_digest_to_blockchain(digest: str, private_key_wif: str) -> str:
    """
    Creates and broadcasts a Bitcoin Testnet transaction with an OP_RETURN output.
    """
    if not private_key_wif:
        raise ValueError("WALLET_PRIVATE_KEY was not provided.")

    key = PrivateKeyTestnet(wif=private_key_wif)
    
    try:
        tx_hash = key.send(
            outputs=[],
            message=digest,
            combine=False
        )
        return tx_hash
    except Exception:
        # Keep traceback for debugging purposes, but no other printing.
        traceback.print_exc(file=sys.stderr)
        raise

# --- CLOUD FUNCTION ---
# The 'secrets' parameter tells Cloud Functions to grant access to the specified secret.
@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=False)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
    # Access the secret value from the defined secret parameter
    private_key = WALLET_PRIVATE_KEY.value()

    logging.info(f"Received request: {req.data}")
    try:
        file_digest = req.data.get("digest")
        if not file_digest:
            # Use HttpsError for client-facing errors
            raise https_fn.HttpsError(
                code=https_fn.FunctionsErrorCode.INVALID_ARGUMENT,
                message="Missing file digest."
            )
        logging.info(f"Processing digest: {file_digest}")
        transaction_id = process_appopreturn_digest_to_blockchain(
            digest=file_digest,
            private_key_wif=private_key
        )
        return {"transaction_id": transaction_id, "network": "testnet4"}
    except Exception as e:
        # Log the original exception for debugging
        logging.error(f"An error occurred: {e}")
        traceback.print_exc(file=sys.stderr)
        # Re-raise exceptions as a generic internal error for the client
        raise https_fn.HttpsError(
            code=https_fn.FunctionsErrorCode.INTERNAL,
            message="An internal error occurred."
        )
# --- END CLOUD FUNCTION ---


def main():
    """
    A simple main function for local testing.
    This now reads the key from the .env file using a different name
    to avoid conflicts with the deployment process.
    """
    private_key_from_env = os.getenv("LOCAL_WALLET_PRIVATE_KEY")
    if not private_key_from_env:
        print("Error: LOCAL_WALLET_PRIVATE_KEY not found in .env file for local testing.", file=sys.stderr)
        return
        
    textencoded="""HelloWorld""".encode('utf-8')
    hash_object = hashlib.sha256(textencoded)
    hex_digest = hash_object.hexdigest()

    try:
        print(process_appopreturn_digest_to_blockchain(
            digest=hex_digest,
            private_key_wif=private_key_from_env
        ))
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
