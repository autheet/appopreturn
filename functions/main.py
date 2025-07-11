import re
import os
from dotenv import load_dotenv
from firebase_functions import https_fn
from blockcypher import create_unsigned_tx, make_tx_signatures, broadcast_signed_transaction

# Load environment variables from .env file
load_dotenv()

def process_appopreturn_digest_to_blockchain(digest: str, blockchain: str = 'testnet4') -> str:
    """
    Processes the digest and sends it to the specified blockchain using Blockcypher.

    Args:
        digest: The SHA-256 digest. Must be a 64-character hex string.
        blockchain: The target blockchain ('testnet4' or 'mainnet'). Defaults to 'testnet4'.

    Returns:
        The transaction ID of the OP_RETURN transaction.
    """
    # 1. Validate the digest
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest, re.IGNORECASE):
        raise ValueError("Invalid digest format. Must be a 64-character hex string.")

    # 2. Map blockchain argument to blockcypher's coin_symbol
    coin_symbol = 'bcy' if blockchain == 'testnet4' else 'btc'

    # 3. Get credentials from environment variables
    private_key = os.getenv("WALLET_PRIVATE_KEY")
    api_token = os.getenv("BLOCKCYPHER_API_TOKEN")

    if not private_key or not api_token:
        raise ValueError("Missing environment variables. Ensure WALLET_PRIVATE_KEY and BLOCKCYPHER_API_TOKEN are set.")

    # 4. Create an unsigned transaction with OP_RETURN
    try:
        # Note: Blockcypher requires the OP_RETURN data to be hex-encoded.
        # Since our digest is already a hex string, we can use it directly.
        unsigned_tx = create_unsigned_tx(
            outputs=[{'value': 0, 'script_type': 'null-data', 'script': digest}],
            coin_symbol=coin_symbol,
            api_key=api_token
        )

        # 5. Sign the transaction
        tx_signatures = make_tx_signatures(
            txs_to_sign=unsigned_tx['tosign'],
            privkey_list=[private_key]
        )

        # 6. Broadcast the signed transaction
        signed_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            coin_symbol=coin_symbol,
            api_key=api_token
        )

        return signed_tx['tx']['hash']

    except Exception as e:
        print(f"Error during Blockcypher transaction: {e}")
        # In a production environment, you'd want more specific error handling
        raise

@https_fn.on_call(enforce_app_check=True)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet4 blockchain.
    """
    try:
        file_digest = req.data.get("digest")
        if not file_digest:
            raise https_fn.CallableException(https_fn.FunctionsErrorCode.INVALID_ARGUMENT, "Missing file digest.")

        transaction_id = process_appopreturn_digest_to_blockchain(
            digest=file_digest,
            blockchain='testnet4'
        )

        return {"transaction_id": transaction_id, "network": "testnet4"}

    except ValueError as e:
        raise https_fn.CallableException(https_fn.FunctionsErrorCode.INVALID_ARGUMENT, str(e))
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise https_fn.CallableException(https_fn.FunctionsErrorCode.INTERNAL, "An internal error occurred.")
