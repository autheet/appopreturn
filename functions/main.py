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

# --- UNTOUCHED CLOUD FUNCTION ---
@https_fn.on_call(enforce_app_check=True)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
    try:
        file_digest = req.data.get("digest")
        if not file_digest:
            raise https_fn.CallableException(https_fn.FunctionsErrorCode.INVALID_ARGUMENT, "Missing file digest.")
        transaction_id = process_appopreturn_digest_to_blockchain(digest=file_digest)
        return {"transaction_id": transaction_id, "network": "testnet4"}
    except Exception as e:
        raise https_fn.CallableException(https_fn.FunctionsErrorCode.INTERNAL, str(e))
# --- END UNTOUCHED CLOUD FUNCTION ---


def main():
    """A simple main function for local testing. No output on success."""
    textencoded="""HelloWorld""".encode('utf-8')
    hash_object = hashlib.sha256(textencoded)
    hex_digest = hash_object.hexdigest()

    try:
        # Silently ensure dependencies are installed
        os.system(f"{sys.executable} -m pip install -r functions/requirements.txt --upgrade > /dev/null 2>&1")
        process_appopreturn_digest_to_blockchain(digest=hex_digest)
    except Exception:
        # Exit with a failure code on error. Traceback is printed from the inner function.
        sys.exit(1)

if __name__ == "__main__":
    main()
