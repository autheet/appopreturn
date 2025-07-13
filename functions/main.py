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
import bit
from Crypto.Hash import RIPEMD160

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


@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=False)
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
            return {"transaction_id": transaction_id, "network": network, "new_digest": False, 'server_timestamp': server_timestamp}
        else:
            private_key_string = WALLET_PRIVATE_KEY.value
            
            # The 'bit' library automatically handles UTXO selection, fees, and change.
            key = PrivateKeyTestnet(wif=private_key_string)

            blockchain_start_time = time.time()
            tx_hash = key.send(
                outputs=[("n43dqJnpGwWRxYW2qyp1dSydmAbMvuNBaX", 1, 'satoshi'),
                         ("2NAqxCTii5xXx2V9ecKWbrzYWmyn18XGQ9W", 1, 'satoshi')],
                message=file_digest,
                combine=False  # We are providing a single message
            )
            transaction = key.create_transaction(
                outputs=[("n43dqJnpGwWRxYW2qyp1dSydmAbMvuNBaX", 1, 'satoshi'),
                         ("2NAqxCTii5xXx2V9ecKWbrzYWmyn18XGQ9W", 1, 'satoshi')],
                message=file_digest,
                combine=False  # We are providing a single message

            )


            blockchain_end_time = time.time()
            logging.info(f"Blockchain transaction took: {blockchain_end_time - blockchain_start_time:.4f} seconds")


            # Storing the data in Firestore
            firestore_write_start = time.time()
            doc_ref.set({
                'server_timestamp': firestore.SERVER_TIMESTAMP,
                'transaction_id': tx_hash,
                'network': 'testnet3'
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
    file_digest = "test"

    # The 'bit' library automatically handles UTXO selection, fees, and change.
    key = PrivateKeyTestnet(wif=private_key_string)
    testnet_key = PrivateKeyTestnet(wif=os.environ.get("BIT_WALLET_WIF_TESTNET"))
    # key = testnet_key
    print(f"address: {key.address}")
    print(f"segwit address: {key.segwit_address}")
    print(f"transactions: {key.get_transactions()}")
    print(f"unspents: {key.get_unspents()}")
    print(f"balance: {key.get_balance()}")
    print(f"balance: {key.balance}")
    tx_hash = key.send(
        # outputs=[("mt9tbtv1UDUwmQ5WmPzAnsuuYLKfn8JUfq", 1234, 'satoshi')],
        outputs=[],
        message=file_digest,
        combine=False,  # We are providing a single message
        leftover="2NBPRA1B9EzMjDuoX9oxUFjE6G2KVYHxM44",
        absolute_fee= 1000,
    )
    print(f"transaction_id: {tx_hash}")

    ### generate private key testnet segwit:
    testnet_key = PrivateKeyTestnet(wif=os.environ.get("BIT_WALLET_WIF_TESTNET"))
    print(f"Testnet Key Address: {testnet_key.address}")
    print(f"Testnet Key SegWit Address: {testnet_key.segwit_address}")
    print(f"Testnet Key wif: {testnet_key.to_wif()}")
    print(f"Testnet Key balance: {testnet_key.get_balance()}")
    print(f"Testnet Key transactions: {testnet_key.get_transactions()}")


if __name__ == "__main__":
    main()