import firebase_admin
import logging
from dotenv import load_dotenv
from firebase_functions import https_fn
from firebase_functions.params import SecretParam
from bit import PrivateKeyTestnet

# --- Initialize Firebase Admin SDK ---
firebase_admin.initialize_app()
# -----------------------------------

# Load environment variables from .env file FOR LOCAL TESTING ONLY
# load_dotenv()

# Define the secret parameter using the standard pattern
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
        
        # Access the secret's value using the canonical .value() method
        # and clean it of any potential whitespace.
        private_key_string = WALLET_PRIVATE_KEY.value()
        
        # Create the key object and send the transaction
        tx_hash = PrivateKeyTestnet(wif=private_key_string).send(
            outputs=[],
            message=file_digest,
            combine=False
        )
        
        # Return the successful result
        return {"transaction_id": tx_hash, "network": "testnet4"}
        
    except Exception as e:
        # Log the full error for debugging
        logging.error(f"Caught unhandled exception: {e}")
        raise https_fn.HttpsError(
            code=https_fn.FunctionsErrorCode.INTERNAL,
            message=f"An internal error occurred: {e}"
        )
