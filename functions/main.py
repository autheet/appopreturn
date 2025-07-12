import os
import hashlib
import sys
import traceback
import logging
import firebase_admin
from dotenv import load_dotenv
from firebase_functions import https_fn
from firebase_functions.params import SecretParam
from bit import PrivateKeyTestnet
from Crypto.Hash import RIPEMD160

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
    except Exception as e:
        # Keep traceback for debugging purposes, but no other printing.
        traceback.print_exc(file=sys.stderr)
        raise e

# --- CLOUD FUNCTION ---
@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=False)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
    try:
        # --- START DEBUG LOGGING ---
        logging.info("--- DEBUGGING ---")
        logging.info(f"Type of req.data: {type(req.data)}")
        logging.info(f"Value of req.data: {req.data}")
        logging.info(f"Type of WALLET_PRIVATE_KEY: {type(WALLET_PRIVATE_KEY)}")
        logging.info("--- END DEBUGGING ---")
        # --- END DEBUG LOGGING ---

        private_key = WALLET_PRIVATE_KEY.value()

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
        logging.error(f"Caught unhandled exception: {e}")
        traceback.print_exc(file=sys.stderr)
        # Re-raise exceptions as a generic internal error for the client
        raise https_fn.HttpsError(
            code=https_fn.FunctionsErrorCode.INTERNAL,
            message=f"An internal error occurred: {e}"
        )
# --- END CLOUD FUNCTION ---


def main():
    """
    A simple main function for local testing.
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
