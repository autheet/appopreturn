import firebase_admin
from firebase_admin import firestore
import logging
import traceback
import os
import time
from dotenv import load_dotenv
from firebase_functions import https_fn
from firebase_functions.params import SecretParam
from os.path import join, dirname
import requests
import random
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Import the library and the specific module we need to patch
from bit import PrivateKeyTestnet, crypto
from bit.network.meta import Unspent
from Crypto.Hash import RIPEMD160

# Import the bitcoinlib library components needed for broadcasting
from bitcoinlib.services.mempool import MempoolClient

# Create a global requests session for connection pooling
# This helps reduce overhead for multiple HTTP requests within a single function invocation
session = requests.Session()



# --- Resilient, Multi-API Data Fetchers with Consensus ---

# Decorator for retrying API calls with exponential backoff
@retry(
    stop=stop_after_attempt(5),  # Max 5 attempts
    wait=wait_exponential(multiplier=1, min=2, max=10),  # Wait 2, 4, 8, 10, 10 seconds
    retry=retry_if_exception_type(requests.exceptions.RequestException)  # Retry only on request-related exceptions
)
def _fetch_url(url, timeout=15, method='GET', json_data=None, data=None):
    """Helper to make robust HTTP requests with retries."""
    logging.info(
        f"Fetching URL: {url} (Attempt {retry.statistics['attempt_number'] if hasattr(retry, 'statistics') else 1})")
    try:
        if method == 'GET':
            response = session.get(url, timeout=timeout)
        elif method == 'POST':
            if json_data:
                response = session.post(url, json=json_data, timeout=timeout)
            else:
                response = session.post(url, data=data, timeout=timeout)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        logging.warning(f"Request to {url} failed: {e}. Retrying...")
        raise  # Re-raise to trigger tenacity retry


# UTXO Providers
def get_unspent_from_mempool(address):
    """Fetches UTXOs from mempool.space."""
    logging.info(f"Attempting to fetch UTXOs from mempool.space for {address}")
    tip_height_url = "https://mempool.space/testnet/api/blocks/tip/height"
    tip_height_r = _fetch_url(tip_height_url)
    current_height = int(tip_height_r.text)

    url = f"https://mempool.space/testnet/api/address/{address}/utxo"
    r = _fetch_url(url)
    if r.status_code == 404:
        logging.info(f"Mempool.space returned 404 for {address}, assuming no UTXOs.")
        return []  # Address with no UTXOs

    utxos = r.json()
    unspents = []
    for utxo in utxos:
        try:
            # Ensure all required keys exist before accessing
            value = utxo['value']
            txid = utxo['txid']
            vout = utxo['vout']
            scriptpubkey = utxo.get('scriptpubkey')  # Use .get() for safety

            if scriptpubkey is None:
                logging.warning(f"Mempool.space UTXO missing 'scriptpubkey' for txid {txid}, vout {vout}. Skipping.")
                continue

            confirmations = 0
            if utxo.get('status', {}).get('confirmed') and utxo['status'].get('block_height'):
                confirmations = current_height - utxo['status']['block_height'] + 1

            unspents.append(Unspent(value, confirmations, scriptpubkey, txid, vout))
        except KeyError as e:
            logging.error(f"Mempool.space UTXO parsing error: Missing key {e} in UTXO: {utxo}")
            continue  # Skip malformed UTXO
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from mempool.space")
    return unspents


def get_unspent_from_blockchair(address):
    """Fetches UTXOs from blockchair.com."""
    logging.info(f"Attempting to fetch UTXOs from blockchair.com for {address}")
    url = f"https://api.blockchair.com/bitcoin/testnet/dashboards/address/{address}?limit=1000"
    r = _fetch_url(url)
    data = r.json().get('data', {})
    utxos = data.get(address, {}).get('utxo', [])

    unspents = []
    for utxo in utxos:
        try:
            value = utxo['value']
            confirmations = utxo['confirmations']
            script_hex = utxo.get('script_hex')  # Use .get() for safety
            transaction_hash = utxo['transaction_hash']
            index = utxo['index']

            if script_hex is None:
                logging.warning(
                    f"Blockchair UTXO missing 'script_hex' for txid {transaction_hash}, index {index}. Skipping.")
                continue

            unspents.append(
                Unspent(value, confirmations, script_hex, transaction_hash, index))
        except KeyError as e:
            logging.error(f"Blockchair UTXO parsing error: Missing key {e} in UTXO: {utxo}")
            continue
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from blockchair.com")
    return unspents


def get_unspent_from_bitaps(address):
    """Fetches UTXOs from bitaps.com."""
    logging.info(f"Attempting to fetch UTXOs from bitaps.com for {address}")
    url = f"https://api.bitaps.com/btc/testnet/v1/address/unspents/{address}"
    r = _fetch_url(url)
    data = r.json().get('data', {})
    utxos = data.get('list', [])

    unspents = []
    for utxo in utxos:
        try:
            value = utxo['value']
            confirmations = utxo['confirmations']
            scriptPubKey = utxo.get('scriptPubKey')  # Use .get() for safety
            txId = utxo['txId']
            vOut = utxo['vOut']

            if scriptPubKey is None:
                logging.warning(f"Bitaps UTXO missing 'scriptPubKey' for txId {txId}, vOut {vOut}. Skipping.")
                continue

            unspents.append(Unspent(value, confirmations, scriptPubKey, txId, vOut))
        except KeyError as e:
            logging.error(f"Bitaps UTXO parsing error: Missing key {e} in UTXO: {utxo}")
            continue
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from bitaps.com")
    return unspents


def get_unspent_from_blockcypher(address):
    """Fetches UTXOs from blockcypher.com."""
    logging.info(f"Attempting to fetch UTXOs from blockcypher.com for {address}")
    url = f"https://api.blockcypher.com/v1/btc/test3/addrs/{address}?unspentOnly=true"
    r = _fetch_url(url)
    data = r.json()
    utxos = data.get('txrefs', [])

    unspents = []
    for utxo in utxos:
        try:
            value = utxo['value']
            confirmations = utxo['confirmations']
            script = utxo.get('script')  # Use .get() for safety
            tx_hash = utxo['tx_hash']
            tx_output_n = utxo['tx_output_n']

            if script is None:
                logging.warning(
                    f"Blockcypher UTXO missing 'script' for tx_hash {tx_hash}, tx_output_n {tx_output_n}. Skipping.")
                continue

            unspents.append(
                Unspent(value, confirmations, script, tx_hash, tx_output_n))
        except KeyError as e:
            logging.error(f"Blockcypher UTXO parsing error: Missing key {e} in UTXO: {utxo}")
            continue
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from blockcypher.com")
    return unspents


def get_unspents_resiliently(address):
    """Tries a list of API providers to fetch UTXOs until one succeeds."""
    providers = [
        get_unspent_from_mempool,
        get_unspent_from_blockchair,
        get_unspent_from_bitaps,
        get_unspent_from_blockcypher
    ]
    random.shuffle(providers)  # Shuffle providers for more distributed load/failover
    for provider_func in providers:
        try:
            return provider_func(address)
        except Exception as e:
            logging.warning(f"UTXO Provider {provider_func.__name__} failed: {e}")
    raise Exception("All UTXO API providers failed.")


# Fee Providers
def get_fee_from_mempool():
    """Fetches recommended fee from mempool.space."""
    logging.info("Attempting to fetch fee from mempool.space")
    url = "https://mempool.space/testnet/api/v1/fees/recommended"
    r = _fetch_url(url)
    fees = r.json()
    fee = fees.get('hourFee')
    if fee:
        return fee
    raise ValueError("Mempool.space fee API did not return 'hourFee'.")


def get_fee_from_blockchair():
    """Fetches recommended fee from blockchair.com."""
    logging.info("Attempting to fetch fee from blockchair.com")
    url = "https://api.blockchair.com/bitcoin/testnet/stats"
    r = _fetch_url(url)
    data = r.json().get('data', {})
    fee_per_byte = data.get('suggested_transaction_fee_per_byte_sat')
    if fee_per_byte:
        return fee_per_byte
    raise ValueError("Blockchair stats API did not return 'suggested_transaction_fee_per_byte_sat'.")


def get_fee_from_bitaps():
    """Fetches recommended fee from bitaps.com."""
    logging.info("Attempting to fetch fee from bitaps.com")
    url = "https://api.bitaps.com/btc/testnet/v1/blockchain/fee/estimation"
    r = _fetch_url(url)
    data = r.json()
    fee_per_byte = data.get('medium', {}).get('feeRate')
    if fee_per_byte:
        return fee_per_byte
    raise ValueError("Bitaps fee API did not return 'medium' fee rate.")


def get_fee_from_blockcypher():
    """Fetches recommended fee from blockcypher.com."""
    logging.info("Attempting to fetch fee from blockcypher.com")
    url = "https://api.blockcypher.com/v1/btc/test3"
    r = _fetch_url(url)
    data = r.json()
    # Fee is in satoshis per kilobyte, convert to sat/vB
    fee_per_kb = data.get('medium_fee_per_kb')
    if fee_per_kb:
        fee_per_byte = fee_per_kb / 1000
        return fee_per_byte
    raise ValueError("Blockcypher API did not return 'medium_fee_per_kb'.")


def get_fee_with_random_retry_and_average():
    """
    Chooses a random API for fee, retries with another random API if the first fails.
    If two successful results are obtained, it averages them and divides by 5.
    If only one is successful, it uses that one.
    """
    fee_providers = [
        get_fee_from_mempool,
        get_fee_from_blockchair,
        get_fee_from_bitaps,
        get_fee_from_blockcypher
    ]

    # Create a shuffled copy to pick from without modifying the original list
    available_providers = list(fee_providers)
    random.shuffle(available_providers)

    successful_fees = []

    # Try to get up to two successful results from distinct providers
    for _ in range(min(2, len(available_providers))):
        if not available_providers:  # No more providers to try
            break

        # Pick a random provider from the remaining available ones
        provider_func = available_providers.pop(random.randrange(len(available_providers)))

        try:
            fee = provider_func()
            successful_fees.append(fee)
            logging.info(f"Got fee from {provider_func.__name__}: {fee} sat/vB")
            if len(successful_fees) == 2:  # Stop if we have two successful fees for averaging
                break
        except Exception as e:
            logging.warning(f"Fee provider {provider_func.__name__} failed: {e}. Trying another random provider...")
            continue  # Continue to the next iteration to try another provider

    if len(successful_fees) >= 2:
        # Take the average of the two delivered results and divide by 5
        avg_fee = sum(successful_fees[:2]) / 2
        final_fee = int(avg_fee / 5)
        logging.info(
            f"Two fees obtained ({successful_fees[0]}, {successful_fees[1]}). Averaging and dividing by 5: {final_fee} sat/vB")
        return max(1, final_fee)  # Ensure fee is at least 1 sat/vB
    elif len(successful_fees) == 1:
        # If only one API succeeded, use its result and divide by 5
        final_fee = int(successful_fees[0] / 5)
        logging.info(f"Only one fee obtained ({successful_fees[0]}). Dividing by 5: {final_fee} sat/vB")
        return max(1, final_fee)  # Ensure fee is at least 1 sat/vB
    else:
        logging.warning("No fee providers succeeded after multiple attempts. Falling back to default fee.")
        return 25  # Fallback fee


# Broadcast Providers
def broadcast_with_mempool(tx_hex):
    """Broadcasts transaction using mempool.space."""
    logging.info("Broadcasting with mempool.space...")
    # MempoolClient handles its own sessions/requests, so we don't use our global session here.
    # It also has its own retry logic, so we don't apply the _fetch_url decorator directly here.
    provider = MempoolClient(network='testnet', denominator=100000000, base_url='https://mempool.space/testnet/api/')
    response = provider.sendrawtransaction(tx_hex)
    if response and 'txid' in response:
        return response['txid']
    raise Exception(f"Mempool broadcast failed. Response: {response}")


def broadcast_with_blockchair(tx_hex):
    """Broadcasts transaction using blockchair.com."""
    logging.info("Broadcasting with blockchair.com...")
    url = "https://api.blockchair.com/bitcoin/testnet/push/transaction"
    response = _fetch_url(url, method='POST', data={'data': tx_hex})
    data = response.json().get('data', {})
    txid = data.get('transaction_hash')
    if txid:
        return txid
    raise Exception(f"Blockchair broadcast failed. Response: {data}")


def broadcast_with_blockcypher(tx_hex):
    """Broadcasting with blockcypher.com."""
    logging.info("Broadcasting with blockcypher.com...")
    url = "https://api.blockcypher.com/v1/btc/test3/txs/push"
    response = _fetch_url(url, method='POST', json_data={'tx': tx_hex})
    data = response.json().get('tx', {})
    txid = data.get('hash')
    if txid:
        return txid
    raise Exception(f"Blockcypher broadcast failed. Response: {data}")


def broadcast_with_bitaps(tx_hex):
    """Broadcasts transaction using bitaps.com."""
    logging.info("Broadcasting with bitaps.com...")
    url = "https://api.bitaps.com/btc/testnet/v1/blockchain/transaction/broadcast"
    response = _fetch_url(url, method='POST', json_data={'rawTransaction': tx_hex})
    txid = response.json().get('txId')
    if txid:
        return txid
    raise Exception(f"Bitaps broadcast failed. Response: {response.text}")


def broadcast_with_blockstream(tx_hex):
    """Broadcasts transaction using blockstream.info."""
    logging.info("Broadcasting with blockstream.info...")
    url = "https://blockstream.info/testnet/api/tx"
    response = _fetch_url(url, method='POST', data=tx_hex)
    txid = response.text
    if len(txid) == 64:  # A valid TXID is 64 hex characters
        return txid
    raise Exception(f"Blockstream broadcast failed. Response: {txid}")


def broadcast_resiliently(tx_hex):
    """Tries a list of API providers to broadcast a transaction until one succeeds."""
    providers = [
        broadcast_with_mempool,
        broadcast_with_blockchair,
        broadcast_with_blockcypher,
        broadcast_with_bitaps,
        broadcast_with_blockstream
    ]
    random.shuffle(providers)
    for provider_func in providers:
        try:
            txid = provider_func(tx_hex)
            logging.info(f"Successfully broadcasted with {provider_func.__name__}. TXID: {txid}")
            return txid
        except Exception as e:
            logging.warning(f"Broadcast provider {provider_func.__name__} failed: {e}")
    raise Exception("All broadcast API providers failed.")


# --- Targeted Patch for ripemd160 in the 'bit' library ---
_original_bit_crypto_new = crypto.new


def _patched_bit_crypto_new(name, data=b''):
    """A patched version of 'new' that supports ripemd160."""
    if name == 'ripemd160':
        return RIPEMD160.new(data)
    return _original_bit_crypto_new(name, data)


crypto.new = _patched_bit_crypto_new
# ----------------------------------------------------------

# Load environment variables from .env file for local testing
load_dotenv()

WALLET_PRIVATE_KEY = SecretParam("WALLET_PRIVATE_KEY")


def transaction_function(digest: str, private_key_string: str, db_client=None) -> dict:
    """
    Encapsulates the core transaction creation and broadcast logic.
    Can be called from a Cloud Function or a local main function.

    Args:
        digest (str): The file digest to embed in the transaction.
        private_key_string (str): The WIF private key string for the wallet.
        db_client (firestore.Client, optional): The Firestore client instance.
                                                 If None, Firestore operations are skipped.

    Returns:
        dict: A dictionary containing transaction_id and network.
    """
    logging.info(f"Creating transaction for digest: {digest}")

    key = PrivateKeyTestnet(wif=private_key_string)
    logging.info(f"Wallet loaded for address: {key.address}")

    unspents = get_unspents_resiliently(key.address)
    balance = sum(utxo.amount for utxo in unspents)

    if balance == 0:
        logging.error(f"Wallet for address {key.address} has no funds.")
        raise https_fn.HttpsError(https_fn.FunctionsErrorCode.FAILED_PRECONDITION,
                                  "The wallet has no funds. Please use a testnet faucet.")

    # Get recommended fee using the random-retry-average logic
    recommended_fee_sat_per_byte = get_fee_with_random_retry_and_average()
    logging.info(f"Using calculated fee rate: {recommended_fee_sat_per_byte} sat/vB")

    raw_tx_hex = key.create_transaction(
        outputs=[],
        message=digest,
        unspents=unspents,
        fee=recommended_fee_sat_per_byte
    )
    logging.info("Raw transaction hex created.")

    tx_hash = broadcast_resiliently(raw_tx_hex)

    if db_client:
        doc_ref = db_client.collection('digestdata_public').document(digest)
        firestore_write_start = time.time()
        doc_ref.set({
            'server_timestamp': firestore.SERVER_TIMESTAMP,
            'transaction_id': tx_hash,
            'network': 'testnet3'
        })
        firestore_write_end = time.time()
        logging.info(f"Firestore write took: {firestore_write_end - firestore_write_start:.4f} seconds")

    return {"transaction_id": tx_hash, "network": "testnet3"}


@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=True)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet blockchain.
    Creates transactions with 'bit' (patched) and broadcasts with 'bitcoinlib'.
    """
    # Initialize Firebase Admin SDK once globally for performance.
    # This allows the initialized instances to be reused across multiple invocations
    # of the same function instance, reducing cold start times and overall execution latency.
    if not firebase_admin._apps:
        firebase_admin.initialize_app()

    # Initialize Firestore client globally
    db = firestore.client()

    total_start_time = time.time()
    try:
        file_digest = req.data.get("digest")
        if not file_digest:
            raise https_fn.HttpsError(https_fn.FunctionsErrorCode.INVALID_ARGUMENT, "Missing file digest.")

        doc_ref = db.collection('digestdata_public').document(file_digest)

        firestore_read_start = time.time()
        doc = doc_ref.get()
        firestore_read_end = time.time()
        logging.info(f"Firestore read took: {firestore_read_end - firestore_read_start:.4f} seconds")

        if doc.exists:
            doc_dict = doc.to_dict()
            total_end_time = time.time()
            logging.info(f"Total execution time for existing digest: {total_end_time - total_start_time:.4f} seconds")
            return {
                "transaction_id": doc_dict.get('transaction_id'),
                "network": doc_dict.get('network'),
                "new_digest": False,
                'server_timestamp': doc_dict.get('server_timestamp')
            }
        else:
            private_key_string = WALLET_PRIVATE_KEY.value

            # Call the new transaction_function
            result = transaction_function(file_digest, private_key_string, db_client=db)

            total_end_time = time.time()
            logging.info(f"Total execution time for new digest: {total_end_time - total_start_time:.4f} seconds")
            return {"transaction_id": result['transaction_id'], "network": result['network'], "new_digest": True}

    except Exception as e:
        logging.error(f"Caught unhandled exception: {e}", exc_info=True)
        total_end_time = time.time()
        logging.info(f"Total execution time with error: {total_end_time - total_start_time:.4f} seconds")
        raise https_fn.HttpsError(https_fn.FunctionsErrorCode.INTERNAL, f"An internal error occurred: {e}")


def main():
    """
    Local testing function to demonstrate the two-library strategy.
    """
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path)
    private_key_string = os.environ.get("LOCAL_WALLET_PRIVATE_KEY")
    file_digest = f"local_test_{int(time.time())}"

    if not private_key_string:
        print("Error: LOCAL_WALLET_PRIVATE_KEY not found in .env file.")
        return

    print("--- Strategy: Create (bit) -> Broadcast (bitcoinlib with MempoolClient) ---")

    try:
        # Call the new transaction_function
        result = transaction_function(file_digest, private_key_string, db_client=None)  # No Firestore for local main

        print(f"  - Success! TXID: {result['transaction_id']}")
        print(f"  - View on block explorer: https://mempool.space/testnet/tx/{result['transaction_id']}")


    except Exception as e:
        print(f"\nAn unexpected error occurred during transaction creation: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
