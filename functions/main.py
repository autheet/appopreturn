import firebase_admin
import logging
import traceback
from dotenv import load_dotenv
from firebase_functions import https_fn
from firebase_functions.params import SecretParam
from bit import PrivateKeyTestnet
from Crypto.Hash import RIPEMD160
import hashlib

# --- Initialize Firebase Admin SDK ---
# This is required for the Firebase runtime to operate correctly,
# including handling App Check tokens.
firebase_admin.initialize_app()
# -----------------------------------


# --- Polyfill for ripemd160 ---
# The standard Python hashlib does not include ripemd160. The 'bit' library
# requires it. We must monkey-patch the hashlib library to add it.
try:
    hashlib.new('ripemd160', b'hello')
except ValueError:
    logging.info("Adding ripemd160 to hashlib")
    _old_new = hashlib.new
    def _new(name, data=b''):
        if name == 'ripemd160':
            return RIPEMD160.new(data)
        return _old_new(name, data)
    hashlib.new = _new
# -----------------------------


# Load environment variables from .env file FOR LOCAL TESTING ONLY
# load_dotenv()

# Define the secret parameter. The Firebase runtime will populate this
# variable with the secret's string value at runtime.
WALLET_PRIVATE_KEY = SecretParam("WALLET_PRIVATE_KEY")


@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=False)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
    try:
        # Get the digest from the request payload
        file_digest = req.data.get("digest")
        if not file_digest:
            raise https_fn.HttpsError(
                code=https_fn.FunctionsErrorCode.INVALID_ARGUMENT,
                message="Missing file digest."
            )
        
        # Access the secret's value as an attribute.
        private_key_string = WALLET_PRIVATE_KEY.value
        
        # Create the key object
        key = PrivateKeyTestnet(wif=private_key_string)
        
        # Create, sign, and broadcast the transaction
        tx_hash = key.send(
            outputs=[],
            message=file_digest,
            combine=False
        )
        
        # Return the successful result
        return {"transaction_id": tx_hash, "network": "testnet4"}
        
    except Exception as e:
        # Log the full error for debugging, including stack trace
        logging.error(f"Caught unhandled exception: {e}")
        logging.error(traceback.format_exc()) # Log the full stack trace
        raise https_fn.HttpsError(
            code=https_fn.FunctionsErrorCode.INTERNAL,
            message=f"An internal error occurred: {e}"
        )
