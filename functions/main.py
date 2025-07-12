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

# --- CLOUD FUNCTION ---
@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=False)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
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

    try:
        # At this point inside the function, WALLET_PRIVATE_KEY is the secret's string value.
        private_key = WALLET_PRIVATE_KEY

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
    print("Local testing of process_appopreturn_digest_to_blockchain is disabled because it is nested.")

if __name__ == "__main__":
    main()
