import firebase_admin
from firebase_admin import firestore
import logging
import traceback
import os
import time
from dotenv import load_dotenv
from firebase_functions import https_fn
from firebase_functions.params import SecretParam
import os
from os.path import join, dirname
from dotenv import load_dotenv
# Import the library and the specific module we need to patch
from bit import PrivateKeyTestnet, crypto
from bit.network import NetworkAPI
import bit
from Crypto.Hash import RIPEMD160
# Import the bitcoinlib library
from bitcoinlib.wallets import Wallet, WalletError
from bitcoinlib.services.services import Service
from bitcoinlib.services.mempool import MempoolClient
from bitcoinlib.transactions import Transaction
# CORRECTED: Import Script class only
from bitcoinlib.scripts import Script

# --- Targeted Patch for ripemd160 in the 'bit' library ---
# The Google Cloud Functions environment lacks native ripemd160 support.
# The 'bit' library imports hashlib.new once at startup. To fix this,
# we replace the 'new' function *within the bit.crypto module* with our own
# version that can handle ripemd160.

# Store the original 'new' function from the bit.crypto module
_original_bit_crypto_new = crypto.new


def _patched_bit_crypto_new(name, data=b''):
    """A patched version of 'new' that supports ripemd160."""
    if name == 'ripemd160':
        return RIPEMD160.new(data)
    # For all other hashes, use the library's original function
    return _original_bit_crypto_new(name, data)


# Apply the patch directly to the module that uses it
crypto.new = _patched_bit_crypto_new
# ----------------------------------------------------------


# Load environment variables from .env file for local testing
# load_dotenv()

# Initialize Firebase Admin SDK
firebase_admin.initialize_app()

WALLET_PRIVATE_KEY = SecretParam("WALLET_PRIVATE_KEY")


@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=True)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet blockchain.
    """
    total_start_time = time.time()
    try:
        file_digest = req.data.get("digest")
        if not file_digest:
            raise https_fn.HttpsError(https_fn.FunctionsErrorCode.INVALID_ARGUMENT, "Missing file digest.")

        db = firestore.client()
        doc_ref = db.collection('digestdata_public').document(file_digest)

        firestore_read_start = time.time()
        doc = doc_ref.get()
        firestore_read_end = time.time()
        logging.info(f"Firestore read took: {firestore_read_end - firestore_read_start:.4f} seconds")

        if doc.exists:
            doc_dict = doc.to_dict()
            transaction_id = doc_dict.get('transaction_id')
            network = doc_dict.get('network')
            server_timestamp = doc_dict.get('server_timestamp')
            total_end_time = time.time()
            logging.info(f"Total execution time for existing digest: {total_end_time - total_start_time:.4f} seconds")
            return {"transaction_id": transaction_id, "network": network, "new_digest": False,
                    'server_timestamp': server_timestamp}
        else:
            private_key_string = WALLET_PRIVATE_KEY.value

            # --- Create with 'bit', broadcast with 'bitcoinlib' ---
            logging.info(f"Creating transaction for digest: {file_digest}")

            # 1. Create raw transaction hex with 'bit'
            key = PrivateKeyTestnet(wif=private_key_string)
            raw_tx_hex = key.create_transaction(
                outputs=[],
                message=file_digest,
                leftover=key.address
            )
            logging.info("Raw transaction hex created.")

            # 2. Broadcast with 'bitcoinlib' using a custom provider
            logging.info("Broadcasting with bitcoinlib...")
            custom_provider = MempoolClient(network='testnet', denominator=100000000,
                                            base_url='https://mempool.space/testnet/api/')
            response = custom_provider.sendrawtransaction(raw_tx_hex)

            if not (response and 'txid' in response):
                raise https_fn.HttpsError(https_fn.FunctionsErrorCode.INTERNAL,
                                          f"Blockchain broadcast failed. Response: {response}")

            tx_hash = response['txid']
            logging.info(f"Transaction broadcasted successfully. TXID: {tx_hash}")

            # Storing the data in Firestore
            firestore_write_start = time.time()
            doc_ref.set({
                'server_timestamp': firestore.SERVER_TIMESTAMP,
                'transaction_id': tx_hash,
                'network': 'testnet3'  # bitcoinlib uses 'testnet3'
            })
            firestore_write_end = time.time()
            logging.info(f"Firestore write took: {firestore_write_end - firestore_write_start:.4f} seconds")

            total_end_time = time.time()
            logging.info(f"Total execution time for new digest: {total_end_time - total_start_time:.4f} seconds")
            return {"transaction_id": tx_hash, "network": "testnet3", "new_digest": True}

    except Exception as e:
        logging.error(f"Caught unhandled exception: {e}", exc_info=True)
        total_end_time = time.time()
        logging.info(f"Total execution time with error: {total_end_time - total_start_time:.4f} seconds")
        raise https_fn.HttpsError(https_fn.FunctionsErrorCode.INTERNAL, f"An internal error occurred: {e}")


def main():
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path)
    private_key_string = os.environ.get("LOCAL_WALLET_PRIVATE_KEY")
    file_digest = "https://appopreturn.autheet.com"

    # --- Strategy: Create with 'bit', broadcast with a custom bitcoinlib provider ---
    print("--- Strategy: Create (bit) -> Broadcast (bitcoinlib with custom provider) ---")

    try:
        # 1. Load key and create raw tx hex with 'bit' library
        key = PrivateKeyTestnet(wif=private_key_string)
        print(f"Wallet loaded for address: {key.address}")

        print(f"\nCreating transaction with message: '{file_digest}' using 'bit'...")
        # CORRECTED: Removed 'absolute_fee' to allow 'bit' to automatically calculate
        # a sufficient fee based on current network conditions.
        raw_tx_hex = key.create_transaction(
            outputs=[],
            message=file_digest,
            leftover=key.address
        )
        print(f"Raw transaction hex created: {raw_tx_hex}")

        # 2. Attempt broadcast with 'bitcoinlib' using a direct client instance
        print("\nBroadcasting with 'bitcoinlib' using custom mempool.space provider...")
        try:
            # Instantiate the client directly with the API URL
            custom_provider = MempoolClient(network='testnet', denominator=100000000,
                                            base_url='https://mempool.space/testnet/api/')

            response = custom_provider.sendrawtransaction(raw_tx_hex)

            # CORRECTED: Extract the 'txid' from the response dictionary
            if response and 'txid' in response:
                tx_hash = response['txid']
                print(f"  - Success via 'bitcoinlib'! TXID: {tx_hash}")
                print(f"  - View on block explorer: https://mempool.space/testnet/tx/{tx_hash}")
            else:
                print(f"  - bitcoinlib broadcast failed. Response: {response}")
        except Exception as e:
            print(f"  - bitcoinlib broadcast failed with an exception: {e}")

    except Exception as e:
        print(f"\nAn unexpected error occurred during transaction creation: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
