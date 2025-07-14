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

# Import the library and the specific module we need to patch
from bit import PrivateKeyTestnet, crypto
from bit.network.meta import Unspent
from Crypto.Hash import RIPEMD160

# Import the bitcoinlib library components needed for broadcasting
from bitcoinlib.services.mempool import MempoolClient


# --- Resilient, Multi-API Data Fetchers with Consensus ---

def get_unspent_from_mempool(address):
    """Fetches UTXOs from mempool.space."""
    logging.info(f"Attempting to fetch UTXOs from mempool.space for {address}")
    tip_height_url = "https://mempool.space/testnet/api/blocks/tip/height"
    tip_height_r = requests.get(tip_height_url, timeout=10)
    tip_height_r.raise_for_status()
    current_height = int(tip_height_r.text)

    url = f"https://mempool.space/testnet/api/address/{address}/utxo"
    r = requests.get(url, timeout=10)
    if r.status_code == 404: return []
    r.raise_for_status()
    utxos = r.json()

    unspents = []
    for utxo in utxos:
        tx_url = f"https://mempool.space/testnet/api/tx/{utxo['txid']}"
        tx_r = requests.get(tx_url, timeout=10)
        tx_r.raise_for_status()
        tx_data = tx_r.json()
        scriptpubkey = tx_data['vout'][utxo['vout']]['scriptpubkey']

        confirmations = current_height - utxo['status']['block_height'] + 1 if utxo.get('status', {}).get(
            'confirmed') else 0

        unspents.append(Unspent(utxo['value'], confirmations, scriptpubkey, utxo['txid'], utxo['vout']))
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from mempool.space")
    return unspents


def get_unspent_from_blockchair(address):
    """Fetches UTXOs from blockchair.com."""
    logging.info(f"Attempting to fetch UTXOs from blockchair.com for {address}")
    url = f"https://api.blockchair.com/bitcoin/testnet/dashboards/address/{address}?limit=1000"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json().get('data', {})
    utxos = data.get(address, {}).get('utxo', [])

    unspents = []
    for utxo in utxos:
        unspents.append(
            Unspent(utxo['value'], utxo['confirmations'], utxo['script_hex'], utxo['transaction_hash'], utxo['index']))
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from blockchair.com")
    return unspents


def get_unspent_from_bitaps(address):
    """Fetches UTXOs from bitaps.com."""
    logging.info(f"Attempting to fetch UTXOs from bitaps.com for {address}")
    url = f"https://api.bitaps.com/btc/testnet/v1/address/unspents/{address}"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json().get('data', {})
    utxos = data.get('list', [])

    unspents = []
    for utxo in utxos:
        # Bitaps provides confirmations directly
        unspents.append(Unspent(utxo['value'], utxo['confirmations'], utxo['scriptPubKey'], utxo['txId'], utxo['vOut']))
    logging.info(f"Successfully fetched {len(unspents)} UTXOs from bitaps.com")
    return unspents


def get_unspent_from_blockcypher(address):
    """Fetches UTXOs from blockcypher.com."""
    logging.info(f"Attempting to fetch UTXOs from blockcypher.com for {address}")
    url = f"https://api.blockcypher.com/v1/btc/test3/addrs/{address}?unspentOnly=true"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    utxos = data.get('txrefs', [])

    unspents = []
    for utxo in utxos:
        # Blockcypher provides confirmations directly
        unspents.append(
            Unspent(utxo['value'], utxo['confirmations'], utxo['script'], utxo['tx_hash'], utxo['tx_output_n']))
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
    for provider_func in providers:
        try:
            return provider_func(address)
        except Exception as e:
            logging.warning(f"Provider {provider_func.__name__} failed: {e}")
    raise Exception("All UTXO API providers failed.")


def get_fee_from_mempool():
    """Fetches recommended fee from mempool.space."""
    logging.info("Attempting to fetch fee from mempool.space")
    url = "https://mempool.space/testnet/api/v1/fees/recommended"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    fees = r.json()
    fee = fees.get('hourFee')
    if fee:
        logging.info(f"Got fee from mempool.space: {fee} sat/vB")
        return fee
    raise ValueError("Mempool.space fee API did not return 'hourFee'.")


def get_fee_from_blockchair():
    """Fetches recommended fee from blockchair.com."""
    logging.info("Attempting to fetch fee from blockchair.com")
    url = "https://api.blockchair.com/bitcoin/testnet/stats"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json().get('data', {})
    fee_per_byte = data.get('suggested_transaction_fee_per_byte_sat')
    if fee_per_byte:
        logging.info(f"Got fee from blockchair.com: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Blockchair stats API did not return 'suggested_transaction_fee_per_byte_sat'.")


def get_fee_from_bitaps():
    """Fetches recommended fee from bitaps.com."""
    logging.info("Attempting to fetch fee from bitaps.com")
    url = "https://api.bitaps.com/btc/testnet/v1/blockchain/fee/estimation"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    fee_per_byte = data.get('medium', {}).get('feeRate')
    if fee_per_byte:
        logging.info(f"Got fee from bitaps.com: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Bitaps fee API did not return 'medium' fee rate.")


def get_fee_from_blockcypher():
    """Fetches recommended fee from blockcypher.com."""
    logging.info("Attempting to fetch fee from blockcypher.com")
    url = "https://api.blockcypher.com/v1/btc/test3"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    # Fee is in satoshis per kilobyte, convert to sat/vB
    fee_per_kb = data.get('medium_fee_per_kb')
    if fee_per_kb:
        fee_per_byte = fee_per_kb / 1000
        logging.info(f"Got fee from blockcypher.com: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Blockcypher API did not return 'medium_fee_per_kb'.")


def get_fee_with_consensus():
    """
    Tries multiple API providers to fetch recommended fees and uses the
    lowest fee from the successful providers.
    """
    providers = [get_fee_from_mempool, get_fee_from_blockchair, get_fee_from_bitaps, get_fee_from_blockcypher]
    fees = []
    for provider_func in providers:
        try:
            fees.append(provider_func())
        except Exception as e:
            logging.warning(f"Fee provider {provider_func.__name__} failed: {e}")

    if fees:
        lowest_fee = int(min(fees))
        logging.info(f"Successfully fetched fees: {fees}. Using lowest value: {lowest_fee} sat/vB")
        return lowest_fee
    else:
        logging.warning("All fee providers failed. Falling back to default fee.")
        return 25  # Fallback fee, slightly increased for safety


def broadcast_with_mempool(tx_hex):
    """Broadcasts transaction using mempool.space."""
    logging.info("Broadcasting with mempool.space...")
    provider = MempoolClient(network='testnet', denominator=100000000, base_url='https://mempool.space/testnet/api/')
    response = provider.sendrawtransaction(tx_hex)
    if response and 'txid' in response:
        return response['txid']
    raise Exception(f"Mempool broadcast failed. Response: {response}")


def broadcast_with_blockchair(tx_hex):
    """Broadcasts transaction using blockchair.com."""
    logging.info("Broadcasting with blockchair.com...")
    url = "https://api.blockchair.com/bitcoin/testnet/push/transaction"
    response = requests.post(url, data={'data': tx_hex}, timeout=10)
    response.raise_for_status()
    data = response.json().get('data', {})
    txid = data.get('transaction_hash')
    if txid:
        return txid
    raise Exception(f"Blockchair broadcast failed. Response: {data}")


def broadcast_with_blockcypher(tx_hex):
    """Broadcasts transaction using blockcypher.com."""
    logging.info("Broadcasting with blockcypher.com...")
    url = "https://api.blockcypher.com/v1/btc/test3/txs/push"
    response = requests.post(url, json={'tx': tx_hex}, timeout=10)
    response.raise_for_status()
    data = response.json().get('tx', {})
    txid = data.get('hash')
    if txid:
        return txid
    raise Exception(f"Blockcypher broadcast failed. Response: {data}")


def broadcast_with_bitaps(tx_hex):
    """Broadcasts transaction using bitaps.com."""
    logging.info("Broadcasting with bitaps.com...")
    url = "https://api.bitaps.com/btc/testnet/v1/blockchain/transaction/broadcast"
    response = requests.post(url, json={'rawTransaction': tx_hex}, timeout=10)
    response.raise_for_status()
    txid = response.json().get('txId')
    if txid:
        return txid
    raise Exception(f"Bitaps broadcast failed. Response: {response.text}")


def broadcast_with_blockstream(tx_hex):
    """Broadcasts transaction using blockstream.info."""
    logging.info("Broadcasting with blockstream.info...")
    url = "https://blockstream.info/testnet/api/tx"
    response = requests.post(url, data=tx_hex, timeout=10)
    response.raise_for_status()
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
    random.shuffle(providers)  # Randomize the order
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

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    firebase_admin.initialize_app()

WALLET_PRIVATE_KEY = SecretParam("WALLET_PRIVATE_KEY")


@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=True)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet blockchain.
    Creates transactions with 'bit' (patched) and broadcasts with 'bitcoinlib'.
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

            # --- Strategy: Create with 'bit', broadcast with 'bitcoinlib' ---
            logging.info(f"Creating transaction for digest: {file_digest}")

            # 1. Load wallet and explicitly check balance before creating transaction
            key = PrivateKeyTestnet(wif=private_key_string)
            logging.info(f"Wallet loaded for address: {key.address}")

            # Manually fetch unspents using our reliable function to bypass 'bit's networking.
            unspents = get_unspents_resiliently(key.address)
            balance = sum(utxo.amount for utxo in unspents)

            if balance == 0:
                logging.error(f"Wallet for address {key.address} has no funds.")
                raise https_fn.HttpsError(https_fn.FunctionsErrorCode.FAILED_PRECONDITION,
                                          "The wallet has no funds. Please use a testnet faucet.")

            # 2. Get recommended fee and create raw transaction hex.
            recommended_fee_sat_per_byte = get_fee_with_consensus() // 5
            logging.info(f"Using recommended fee rate: {recommended_fee_sat_per_byte} sat/vB")

            raw_tx_hex = key.create_transaction(
                outputs=[],
                message=file_digest,
                unspents=unspents,  # Provide the fetched UTXOs directly
                fee=recommended_fee_sat_per_byte  # Set the fee rate
            )
            logging.info("Raw transaction hex created.")

            # 3. Broadcast transaction resiliently
            tx_hash = broadcast_resiliently(raw_tx_hex)

            # 4. Store the new transaction data in Firestore
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
        # 1. Load key and check balance before proceeding
        key = PrivateKeyTestnet(wif=private_key_string)
        print(f"Wallet loaded for address: {key.address}")
        print(f"Wallet loaded for segwit address: {key.segwit_address}")
        print("Checking wallet balance using resilient custom functions...")
        # Manually fetch unspents and calculate balance.
        unspents = get_unspents_resiliently(key.address)
        balance = sum(utxo.amount for utxo in unspents)
        print(f"Wallet balance: {balance} satoshis")

        if balance == 0:
            print("\nERROR: Wallet balance is zero.")
            print(f"Please send testnet bitcoin to this address: {key.address}")
            print("You can use a faucet like https://coinfaucet.eu/en/btc-testnet/")
            return

        # 2. Get recommended fee and create raw tx hex.
        print("\nFetching recommended fee rate...")
        recommended_fee_sat_per_byte = get_fee_with_consensus() // 5
        print(f"Using fee rate: {recommended_fee_sat_per_byte} sat/vB")

        print(f"\nCreating transaction with message: '{file_digest}' using 'bit'...")
        raw_tx_hex = key.create_transaction(
            outputs=[],
            message=file_digest,
            unspents=unspents,  # Provide the fetched UTXOs directly
            fee=recommended_fee_sat_per_byte  # Set the fee rate
        )
        print(f"Raw transaction hex created: {raw_tx_hex[:64]}...")

        # 3. Attempt broadcast resiliently
        print("\nBroadcasting transaction resiliently...")
        tx_hash = broadcast_resiliently(raw_tx_hex)
        print(f"  - Success! TXID: {tx_hash}")
        print(f"  - View on block explorer: https://mempool.space/testnet/tx/{tx_hash}")


    except Exception as e:
        print(f"\nAn unexpected error occurred during transaction creation: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
