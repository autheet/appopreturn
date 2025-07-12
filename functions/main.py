import re
import os
import hashlib
from dotenv import load_dotenv
from firebase_functions import https_fn
from blockcypher import create_unsigned_tx, make_tx_signatures, broadcast_signed_transaction, get_address_details
from bitcoin import privkey_to_address

# Load environment variables from .env file
load_dotenv()

def process_appopreturn_digest_to_blockchain(digest: str, blockchain: str = 'testnet4') -> str:
    """
    Processes the digest and sends it to the specified blockchain using Blockcypher.
    """
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest, re.IGNORECASE):
        raise ValueError("Invalid digest format. Must be a 64-character hex string.")

    coin_symbol = 'bcy' if blockchain == 'testnet4' else 'btc'
    private_key = os.getenv("WALLET_PRIVATE_KEY")
    api_token = os.getenv("BLOCKCYPHER_API_TOKEN")

    if not private_key or not api_token:
        raise ValueError("Missing environment variables. Ensure WALLET_PRIVATE_KEY and BLOCKCYPHER_API_TOKEN are set.")

    # FIX: Specify the correct magicbyte for testnet (111) or mainnet (0).
    # This ensures the address derived from the private key matches the target blockchain.
    magic_byte_for_address = 111 if coin_symbol == 'bcy' else 0
    source_address = privkey_to_address(private_key, magicbyte=magic_byte_for_address)

    print(f"Derived source address: {source_address}") # Debugging line

    try:
        address_details = get_address_details(source_address, coin_symbol=coin_symbol, api_key=api_token)
        if address_details.get('final_n_tx', 0) == 0 or address_details.get('final_balance', 0) == 0:
             raise ValueError(f"The wallet address {source_address} has no funds (UTXOs). Please fund this address on the {blockchain} network.")
    except Exception as e:
         raise ValueError(f"Could not verify funds for address {source_address}. Error: {e}")

    try:
        unsigned_tx = create_unsigned_tx(
            inputs=[{'address': source_address}],
            outputs=[{'value': 0, 'script_type': 'null-data', 'script': digest}],
            coin_symbol=coin_symbol,
            api_key=api_token,
            change_address=source_address
        )

        tx_signatures = make_tx_signatures(
            txs_to_sign=unsigned_tx['tosign'],
            privkey_list=[private_key]
        )

        signed_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            coin_symbol=coin_symbol,
            api_key=api_token
        )

        return signed_tx['tx']['hash']
    except Exception as e:
        error_message = str(e)
        if "Not enough funds" in error_message:
            raise ValueError(f"The wallet address {source_address} does not have enough funds to cover the transaction fee.")
        print(f"Error during Blockcypher transaction: {error_message}")
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

def main():
    """A simple main function for local testing."""
    textencoded="""HelloWorld""".encode('utf-8')
    hash_object = hashlib.sha256(textencoded)
    hex_digest = hash_object.hexdigest()

    print("Attempting to process digest on testnet4...")
    try:
        tx_id = process_appopreturn_digest_to_blockchain(
            digest=hex_digest,
            blockchain='testnet4'
        )
        print(f"Successfully broadcast transaction: {tx_id}")
    except Exception as e:
        print(f"Failed to process transaction. Error: {e}")

if __name__ == "__main__":
    main()
