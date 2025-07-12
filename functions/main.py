import os
import hashlib
import sys
import traceback
from dotenv import load_dotenv
from firebase_functions import https_fn
from bit import PrivateKeyTestnet

# Load environment variables from .env file for local testing
load_dotenv()

def process_appopreturn_digest_to_blockchain(digest: str) -> str:
    """
    Creates and broadcasts a Bitcoin Testnet transaction with an OP_RETURN output.
    """
    private_key_wif = os.getenv("WALLET_PRIVATE_KEY")
    if not private_key_wif:
        raise ValueError("WALLET_PRIVATE_KEY environment variable not set.")

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
@https_fn.on_call(enforce_app_check=False)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
    try:
        file_digest = req.data.get("digest")
        if not file_digest:
            # Use HttpsError for client-facing errors
            raise https_fn.HttpsError(
                code=https_fn.FunctionsErrorCode.INVALID_ARGUMENT,
                message="Missing file digest."
            )
        transaction_id = process_appopreturn_digest_to_blockchain(digest=file_digest)
        return {"transaction_id": transaction_id, "network": "testnet4"}
    except Exception as e:
        # Log the original exception for debugging
        traceback.print_exc(file=sys.stderr)
        # Re-raise exceptions as a generic internal error for the client
        raise https_fn.HttpsError(
            code=https_fn.FunctionsErrorCode.INTERNAL,
            message="An internal error occurred."
        )
# --- END CLOUD FUNCTION ---


def main():
    """A simple main function for local testing. No output on success."""
    textencoded="""HelloWorld""".encode('utf-8')
    hash_object = hashlib.sha256(textencoded)
    hex_digest = hash_object.hexdigest()

    try:
        print(process_appopreturn_digest_to_blockchain(digest=hex_digest))
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
