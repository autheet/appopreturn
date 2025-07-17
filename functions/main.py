from posix import cpu_count

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
import statistics
import decimal
import datetime
# Import the library and the specific module we need to patch
from bit import PrivateKeyTestnet, crypto
from bit.network.meta import Unspent
from Crypto.Hash import RIPEMD160

# Import the bitcoinlib library components needed for broadcasting
from bitcoinlib.services.mempool import MempoolClient


# --- Resilient, Multi-API Data Fetchers with Consensus ---

def get_unspent_from_mempool(address):
    """Fetches UTXOs from mempool.space."""
    print(f"Attempting to fetch UTXOs from mempool.space for {address}")
    tip_height_url = "https://mempool.space/testnet/api/blocks/tip/height"
    tip_height_r = requests.get(tip_height_url, timeout=5)
    tip_height_r.raise_for_status()
    current_height = int(tip_height_r.text)

    url = f"https://mempool.space/testnet/api/address/{address}/utxo"
    r = requests.get(url, timeout=2)
    if r.status_code == 404: raise Exception(f"Address {address} utxo not found in mempool.space")
    r.raise_for_status()
    utxos = r.json()

    unspents = []
    for utxo in utxos:
        tx_url = f"https://mempool.space/testnet/api/tx/{utxo['txid']}"
        tx_r = requests.get(tx_url, timeout=1)
        tx_r.raise_for_status()
        tx_data = tx_r.json()
        scriptpubkey = tx_data['vout'][utxo['vout']]['scriptpubkey']

        confirmations = current_height - utxo['status']['block_height'] + 1 if utxo.get('status', {}).get(
            'confirmed') else 0

        unspents.append(Unspent(utxo['value'], confirmations, scriptpubkey, utxo['txid'], utxo['vout']))
    print(f"Successfully fetched {len(unspents)} UTXOs from mempool.space")
    return unspents


def get_unspent_from_blockchair(address):
    """Fetches UTXOs from blockchair.com."""
    print(f"Attempting to fetch UTXOs from blockchair.com for {address}")
    url = f"https://api.blockchair.com/bitcoin/testnet/dashboards/address/{address}?limit=100"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json().get('data', {})
    utxos = data.get(address, {}).get('utxo', [])

    unspents = []
    for utxo in utxos:
        unspents.append(
            Unspent(utxo['value'], utxo['confirmations'], utxo['script_hex'], utxo['transaction_hash'], utxo['index']))
    print(f"Successfully fetched {len(unspents)} UTXOs from blockchair.com")
    return unspents


def get_unspent_from_bitaps(address):
    """Fetches UTXOs from bitaps.com."""
    print(f"Attempting to fetch UTXOs from bitaps.com for {address}")
    url = f"https://api.bitaps.com/btc/testnet/v1/address/unspents/{address}"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json().get('data', {})
    utxos = data.get('list', [])

    unspents = []
    for utxo in utxos:
        # Bitaps provides confirmations directly
        unspents.append(Unspent(utxo['value'], utxo['confirmations'], utxo['scriptPubKey'], utxo['txId'], utxo['vOut']))
    print(f"Successfully fetched {len(unspents)} UTXOs from bitaps.com")
    return unspents


def get_unspent_from_blockcypher(address):
    """Fetches UTXOs from blockcypher.com."""
    print(f"Attempting to fetch UTXOs from blockcypher.com for {address}")
    # FIX: Added API token handling
    token = BLOCKCYPHER_TOKEN.value if "BLOCKCYPHER_TOKEN" in globals() and BLOCKCYPHER_TOKEN.value else os.environ.get(
        "BLOCKCYPHER_TOKEN")
    url = f"https://api.blockcypher.com/v1/btc/test3/addrs/{address}"
    params = {'unspentOnly': 'true'}
    if token:
        params['token'] = token

    r = requests.get(url, params=params, timeout=3)
    r.raise_for_status()
    data = r.json()
    if 'error' in data:
        raise Exception(f"Blockcypher API returned an error: {data['error']}")
    utxos = data.get('txrefs', [])

    unspents = []
    for utxo in utxos:
        # Blockcypher provides confirmations directly
        unspents.append(
            Unspent(utxo['value'], utxo['confirmations'], utxo['script'], utxo['tx_hash'], utxo['tx_output_n']))
    print(f"Successfully fetched {len(unspents)} UTXOs from blockcypher.com")
    return unspents


def get_unspent_from_blockstream(address):
    """Fetches UTXOs from blockstream.info."""
    print(f"Attempting to fetch UTXOs from blockstream.info for {address}")
    tip_height_url = "https://blockstream.info/testnet/api/blocks/tip/height"
    tip_height_r = requests.get(tip_height_url, timeout=5)
    tip_height_r.raise_for_status()
    current_height = int(tip_height_r.text)

    url = f"https://blockstream.info/testnet/api/address/{address}/utxo"
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    utxos = r.json()

    unspents = []
    for utxo in utxos:
        tx_url = f"https://blockstream.info/testnet/api/tx/{utxo['txid']}"
        tx_r = requests.get(tx_url, timeout=2)
        tx_r.raise_for_status()
        tx_data = tx_r.json()
        scriptpubkey = tx_data['vout'][utxo['vout']]['scriptpubkey']

        confirmations = current_height - utxo['status']['block_height'] + 1 if utxo.get('status', {}).get(
            'confirmed') else 0

        unspents.append(Unspent(utxo['value'], confirmations, scriptpubkey, utxo['txid'], utxo['vout']))
    print(f"Successfully fetched {len(unspents)} UTXOs from blockstream.info")
    if unspents != []:
        return unspents


def get_unspent_from_sochain(address):
    """Fetches UTXOs from sochain.com."""
    print(f"Attempting to fetch UTXOs from sochain.com for {address}")
    url = f"https://sochain.com/api/v2/get_tx_unspent/BTCTEST/{address}"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json().get('data', {})
    utxos = data.get('txs', [])

    unspents = []
    for utxo in utxos:
        # SoChain returns value in BTC, convert to satoshis
        amount_satoshi = int(decimal.Decimal(utxo['value']) * 100_000_000)
        unspents.append(
            Unspent(amount_satoshi, utxo['confirmations'], utxo['script_hex'], utxo['txid'], utxo['output_no']))
    print(f"Successfully fetched {len(unspents)} UTXOs from sochain.com")
    return unspents


def get_unspent_from_insight(address):
    """Fetches UTXOs from test-insight.bitpay.com."""
    print(f"Attempting to fetch UTXOs from test-insight.bitpay.com for {address}")
    url = f"https://test-insight.bitpay.com/api/addr/{address}/utxo"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    utxos = r.json()

    unspents = []
    for utxo in utxos:
        unspents.append(
            Unspent(utxo['satoshis'], utxo['confirmations'], utxo['scriptPubKey'], utxo['txid'], utxo['vout']))
    print(f"Successfully fetched {len(unspents)} UTXOs from test-insight.bitpay.com")
    return unspents


def get_unspents_resiliently(address):
    """Tries a list of API providers to fetch UTXOs until one succeeds."""
    providers = [
        get_unspent_from_mempool,
        get_unspent_from_blockchair,
        # get_unspent_from_bitaps, <- too unreliable, just wastes time
        get_unspent_from_blockcypher,
        get_unspent_from_blockstream,
        # get_unspent_from_sochain, <<- too unreliable, just wastes time
        get_unspent_from_insight
    ]
    random.shuffle(providers)
    unspentsdict = {}

    def find_duplicate_value_oneliner(data_dict):
        """Finds the first duplicate value in a dictionary in one line."""
        values = list(data_dict.values())
        return next((v for i, v in enumerate(values) if v in values[:i]), None)

    for provider_func in providers:
        try:
            unspents = provider_func(address)
            balance = sum(utxo.amount for utxo in unspents) if unspents else 0

            if unspents and balance > 0:
                print(f"Successfully fetched UTXOs using {provider_func.__name__}")
                unspentsdict[provider_func.__name__] = unspents
                if len(unspentsdict) >= 2:
                    duplicate = find_duplicate_value_oneliner(unspentsdict)
                    if duplicate:
                        print(f"Consensus found for UTXOs. Returning result.")
                        return duplicate
            elif unspents is None:
                logging.warning(f"Provider {provider_func.__name__} returned None.")
            elif balance == 0:
                logging.warning(f"Wallet for address {address} has no funds according to {provider_func.__name__}.")


        except Exception as e:
            print(f"Provider {provider_func.__name__} failed: {e}")
    if len(unspentsdict) >= 1:
        logging.warning(f"No consensus or only one UTXO provider succeeded.")
        return next(iter(unspentsdict.values()))
    raise Exception("All UTXO API providers failed.")


def get_fee_from_mempool():
    """Fetches recommended fee from mempool.space."""
    print("Attempting to fetch fee from mempool.space")
    url = "https://mempool.space/testnet/api/v1/fees/recommended"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    fees = r.json()
    fee = fees.get('economyFee')
    if fee:
        print(f"Got fee from mempool.space: {fee} sat/vB")
        return fee
    raise ValueError("Mempool.space fee API did not return 'hourFee'.")


def get_fee_from_blockchair():
    """Fetches recommended fee from blockchair.com."""
    print("Attempting to fetch fee from blockchair.com")
    url = "https://api.blockchair.com/bitcoin/testnet/stats"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json().get('data', {})
    fee_per_byte = data.get('suggested_transaction_fee_per_byte_sat')
    if fee_per_byte:
        print(f"Got fee from blockchair.com: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Blockchair stats API did not return 'suggested_transaction_fee_per_byte_sat'.")


def get_fee_from_bitaps():
    """Fetches recommended fee from bitaps.com."""
    print("Attempting to fetch fee from bitaps.com")
    url = "https://api.bitaps.com/btc/testnet/v1/mempool/fee"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json().get('data', {})
    # Using low fee for minimum
    fee_per_byte = data.get('lowFee', {}).get('feeRate')
    if fee_per_byte:
        print(f"Got fee from bitaps.com: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Bitaps fee API did not return 'lowFee' fee rate.")


def get_fee_from_blockcypher():
    """Fetches recommended fee from blockcypher.com."""
    print("Attempting to fetch fee from blockcypher.com")
    # FIX: Added API token handling
    token = BLOCKCYPHER_TOKEN.value if "BLOCKCYPHER_TOKEN" in globals() and BLOCKCYPHER_TOKEN.value else os.environ.get(
        "BLOCKCYPHER_TOKEN")
    url = "https://api.blockcypher.com/v1/btc/test3"
    params = {}
    if token:
        params['token'] = token

    r = requests.get(url, params=params, timeout=2)
    r.raise_for_status()
    data = r.json()
    if 'error' in data:
        raise Exception(f"Blockcypher API returned an error: {data['error']}")
    # Fee is in satoshis per kilobyte, convert to sat/vB
    fee_per_kb = data.get('low_fee_per_kb')
    if fee_per_kb:
        fee_per_byte = fee_per_kb / 1000
        print(f"Got fee from blockcypher.com: {fee_per_byte} sat/vB")
        return fee_per_byte//3
    raise ValueError("Blockcypher API did not return 'low_fee_per_kb'.")


def get_fee_from_blockstream():
    """Fetches recommended fee from blockstream.info."""
    print("Attempting to fetch fee from blockstream.info")
    url = "https://blockstream.info/testnet/api/fee-estimates"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    fees = r.json()
    min_fee = min(fees, key=fees.get)
    fee_per_byte = fees.get(min_fee)  # get the minimum fee
    if fee_per_byte < 10:
        print(f"Got fee from blockstream.info: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Blockstream fee API did not return a minimum fee.")


def get_fee_from_sochain():
    """Fetches recommended fee from sochain.com."""
    print("Attempting to fetch fee from sochain.com")
    # Using a 6 block confirmation target
    url = "https://sochain.com/api/v2/get_fee_estimate/BTCTEST/6"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json().get('data', {})
    fee_per_byte = data.get('estimated_fee_per_byte')
    if fee_per_byte:
        # SoChain returns fee as a string, convert to float
        fee = float(fee_per_byte)
        print(f"Got fee from sochain.com: {fee} sat/vB")
        return fee
    raise ValueError("SoChain fee API did not return 'estimated_fee_per_byte'.")


def get_fee_from_insight():
    """Fetches recommended fee from test-insight.bitpay.com."""
    print("Attempting to fetch fee from test-insight.bitpay.com")
    # 6 block target for an economy fee
    url = "https://test-insight.bitpay.com/api/utils/estimatefee?nbBlocks=6"
    r = requests.get(url, timeout=2)
    r.raise_for_status()
    data = r.json()
    # API returns fee in BTC/kB. We need sat/vB.
    fee_btc_per_kb = next(iter(data.values()), None)
    if fee_btc_per_kb and fee_btc_per_kb > 0:
        # Convert BTC/kB to sat/vB
        # 1 BTC = 10^8 satoshis. 1 kB = 1000 bytes.
        # (fee_btc_per_kb * 10^8) / 1000 = fee_sat_per_byte
        fee_per_byte = (fee_btc_per_kb * 100_000_000) / 1000
        print(f"Got fee from test-insight.bitpay.com: {fee_per_byte} sat/vB")
        return fee_per_byte
    raise ValueError("Insight fee API did not return a valid fee.")


def get_fee_with_consensus():
    """
    Tries multiple API providers to fetch recommended fees and uses the median.
    """
    providers = [
        get_fee_from_mempool,
        get_fee_from_blockchair,
        # get_fee_from_bitaps, #<- too unreliable
        get_fee_from_blockcypher,
        get_fee_from_blockstream,
        # get_fee_from_sochain, #<- too unreliable, just wastes time
        get_fee_from_insight
    ]
    random.shuffle(providers)  # Shuffle the providers for better distribution
    fees = []
    for provider_func in providers:
        try:
            fee_provider = provider_func()
            if fee_provider >= 20:
                fee_provider = 20
                print(f"Fee provider {provider_func.__name__} returned a too high fee. Using 20 sat/vB")
            fees.append(fee_provider)
        except Exception as e:
            logging.warning(f"Fee provider {provider_func.__name__} failed: {e}")

        if len(fees) >= 2:
            # If at least two providers succeeded, return the average fee
            average_fee = int(sum(fees) / len(fees))
            chosen_fee = average_fee // 3
            if chosen_fee < 1:
                chosen_fee = 1
            print(
                f"Successfully fetched fees from multiple providers: {fees}. Using average value: {average_fee} sat/vB")
            return chosen_fee

    if len(fees) == 1:
        # If only one provider succeeded, use its fee
        single_fee = int(fees[0])
        chosen_fee = single_fee // 3
        if chosen_fee < 1:
            chosen_fee = 1
        print(f"Only one fee provider succeeded: {single_fee} sat/vB")
        return chosen_fee
    else:
        logging.error("All fee providers failed. Falling back to default fee.")
        return 1  # Fallback fee


def broadcast_with_mempool(tx_hex):
    """Broadcasts transaction using mempool.space."""
    print("Broadcasting with mempool.space...")
    provider = MempoolClient(network='testnet', denominator=100000000, base_url='https://mempool.space/testnet/api/')
    response = provider.sendrawtransaction(tx_hex)
    if response and 'txid' in response:
        return response['txid']
    raise Exception(f"Mempool broadcast failed. Response: {response}")


def broadcast_with_blockchair(tx_hex):
    """Broadcasts transaction using blockchair.com."""
    print("Broadcasting with blockchair.com...")
    url = "https://api.blockchair.com/bitcoin/testnet/push/transaction"
    response = requests.post(url, data={'data': tx_hex}, timeout=5)
    response.raise_for_status()
    data = response.json().get('data', {})
    txid = data.get('transaction_hash')
    if txid:
        return txid
    raise Exception(f"Blockchair broadcast failed. Response: {data}")


def broadcast_with_blockcypher(tx_hex):
    """Broadcasts transaction using blockcypher.com."""
    print("Broadcasting with blockcypher.com...")
    # FIX: Added API token handling
    token = BLOCKCYPHER_TOKEN.value if "BLOCKCYPHER_TOKEN" in globals() and BLOCKCYPHER_TOKEN.value else os.environ.get(
        "BLOCKCYPHER_TOKEN")
    url = "https://api.blockcypher.com/v1/btc/test3/txs/push"
    if token:
        url += f"?token={token}"

    response = requests.post(url, json={'tx': tx_hex}, timeout=5)
    response.raise_for_status()
    data = response.json()
    if 'error' in data:
        raise Exception(f"Blockcypher API returned an error: {data['error']}")
    txid = data.get('tx', {}).get('hash')
    if txid:
        return txid
    raise Exception(f"Blockcypher broadcast failed. Response: {data}")


def broadcast_with_bitaps(tx_hex):
    """Broadcasts transaction using bitaps.com."""
    print("Broadcasting with bitaps.com...")
    url = "https://api.bitaps.com/btc/testnet/v1/blockchain/transaction/broadcast"
    response = requests.post(url, json={'rawTransaction': tx_hex}, timeout=5)
    response.raise_for_status()
    txid = response.json().get('txId')
    if txid:
        return txid
    raise Exception(f"Bitaps broadcast failed. Response: {response.text}")


def broadcast_with_blockstream(tx_hex):
    """Broadcasts transaction using blockstream.info."""
    print("Broadcasting with blockstream.info...")
    url = "https://blockstream.info/testnet/api/tx"
    response = requests.post(url, data=tx_hex, timeout=5)
    response.raise_for_status()
    txid = response.text
    if len(txid) == 64:  # A valid TXID is 64 hex characters
        return txid
    raise Exception(f"Blockstream broadcast failed. Response: {txid}")


def broadcast_with_sochain(tx_hex):
    """Broadcasts transaction using sochain.com."""
    print("Broadcasting with sochain.com...")
    url = "https://sochain.com/api/v2/send_tx/BTCTEST"
    response = requests.post(url, json={'tx_hex': tx_hex}, timeout=2)
    response.raise_for_status()
    data = response.json().get('data', {})
    txid = data.get('txid')
    if txid:
        return txid
    raise Exception(f"SoChain broadcast failed. Response: {response.text}")


def broadcast_with_insight(tx_hex):
    """Broadcasts transaction using test-insight.bitpay.com."""
    print("Broadcasting with test-insight.bitpay.com...")
    url = "https://test-insight.bitpay.com/api/tx/send"
    response = requests.post(url, json={'rawtx': tx_hex}, timeout=5)
    response.raise_for_status()
    data = response.json()
    txid = data.get('txid')
    if txid:
        return txid
    raise Exception(f"Insight broadcast failed. Response: {response.text}")


def broadcast_resiliently(tx_hex):
    """Tries a list of API providers to broadcast a transaction until two succeeds. if only one succeeds, returns it, too with a warning"""
    providers = [
        broadcast_with_mempool,
        broadcast_with_blockchair,
        broadcast_with_blockcypher,
        # broadcast_with_bitaps, <- too unreliable, just wastes time
        broadcast_with_blockstream,
        # broadcast_with_sochain, <- too unreliable, just wastes time
        broadcast_with_insight
    ]
    random.shuffle(providers)
    txids = {}

    for provider_func in providers:
        try:
            txid = provider_func(tx_hex)
            print(f"Successfully broadcasted with {provider_func.__name__}. TXID: {txid}")
            txids[f"{provider_func.__name__}"] = txid
            if len(txids) >= 2:
                print(f"broadcasted with {txids}")
                return txid
        except Exception as e:
            logging.warning(f"Broadcast provider {provider_func.__name__} failed: {e}")
    if len(txids) >= 1:
        logging.warning(f"only one broadcast provider succeeded: {txids}")
        return next(iter(txids.values()))
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
## FIX: Define the new secret for the Blockcypher API Token.
# BLOCKCYPHER_TOKEN = SecretParam("BLOCKCYPHER_TOKEN")
os.environ.get("BLOCKCYPHER_TOKEN")

def transact(private_key_string, file_digest):
    # 1. Load wallet and explicitly check balance before creating transaction
    key = PrivateKeyTestnet(wif=private_key_string)
    print(f"Wallet loaded for address: {key.address}")

    recommended_fee_sat_per_byte = get_fee_with_consensus()
    print(f"Using recommended fee rate: {recommended_fee_sat_per_byte} sat/vB")
    # Manually fetch unspents using our reliable function to bypass 'bit's networking.
    unspents = get_unspents_resiliently(key.address)

    raw_tx_hex = key.create_transaction(
        outputs=[],
        message=file_digest,
        unspents=unspents,  # Provide the fetched UTXOs directly
        fee=recommended_fee_sat_per_byte  # Set the fee rate
    )
    print("Raw transaction hex created.")

    # 3. Broadcast transaction resiliently
    try:
        tx_hash = broadcast_resiliently(raw_tx_hex)
        return {"tx_hash": tx_hash, 'network': 'testnet3'}
    except Exception as e:
        print(f"Broadcast failed: {e}")
    print("Increasing fee and retrying...")
    raw_tx_hex = key.create_transaction(
        outputs=[],
        message=file_digest,
        unspents=unspents,  # Provide the fetched UTXOs directly
        fee=recommended_fee_sat_per_byte*3  # Set the fee rate
    )
    tx_hash = broadcast_resiliently(raw_tx_hex)
    return {"tx_hash": tx_hash, 'network': 'testnet3'}


# FIX: Added BLOCKCYPHER_TOKEN to the list of secrets.
@https_fn.on_call(secrets=[WALLET_PRIVATE_KEY], enforce_app_check=True, memory=1024, timeout_sec=180, cpu=2)
def process_appopreturn_request_free(req: https_fn.CallableRequest) -> dict:
    """
    Handles requests from free users for the testnet blockchain.
    Creates transactions with 'bit' (patched) and broadcasts with 'bitcoinlib'.
    """
    os.environ.get("BLOCKCYPHER_TOKEN")
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
        print(f"Firestore read took: {firestore_read_end - firestore_read_start:.4f} seconds")

        if doc.exists:
            doc_dict = doc.to_dict()
            total_end_time = time.time()
            print(f"Total execution time for existing digest: {total_end_time - total_start_time:.4f} seconds")
            return {
                "transaction_id": doc_dict.get('transaction_id'),
                "network": doc_dict.get('network'),
                "new_digest": False,
                'server_timestamp': doc_dict.get('server_timestamp')
            }
        else:
            private_key_string = WALLET_PRIVATE_KEY.value

            # --- Strategy: Create with 'bit', broadcast with 'bitcoinlib' ---
            print(f"Creating transaction for digest: {file_digest}")
            tx = transact(private_key_string, file_digest)
            tx_hash = tx['tx_hash']

            # 4. Store the new transaction data in Firestore
            firestore_write_start = time.time()
            doc_ref.set({
                'server_timestamp': firestore.SERVER_TIMESTAMP,
                'transaction_id': tx_hash,
                'network': 'testnet3'
            })
            firestore_write_end = time.time()
            print(f"Firestore write took: {firestore_write_end - firestore_write_start:.4f} seconds")

            total_end_time = time.time()
            print(f"Total execution time for new digest: {total_end_time - total_start_time:.4f} seconds")
            return {"transaction_id": tx_hash, "network": "testnet3", "new_digest": True}

    except Exception as e:
        logging.error(f"Caught unhandled exception: {e}", exc_info=True)
        total_end_time = time.time()
        print(f"Total execution time with error: {total_end_time - total_start_time:.4f} seconds")
        raise https_fn.HttpsError(https_fn.FunctionsErrorCode.INTERNAL, f"An internal error occurred: {e}")


def main():
    """
    Local testing function to demonstrate the two-library strategy.
    """
    time = datetime.datetime.now()
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path)
    private_key_string = os.environ.get("LOCAL_WALLET_PRIVATE_KEY")
    # FIX: Ensure BLOCKCYPHER_TOKEN is loaded from .env for local testing
    os.environ.get("BLOCKCYPHER_TOKEN")
    file_digest = f"https://appopreturn.autheet.com"

    if not private_key_string:
        print("Error: LOCAL_WALLET_PRIVATE_KEY not found in .env file.")
        return

    print("--- Strategy: Create (bit) -> Broadcast (resiliently) ---")

    try:

        tx = transact(private_key_string, file_digest)
        print("\nBroadcasting transaction resiliently...")
        tx_hash = tx['tx_hash']
        print(f"  - Success! TXID: {tx_hash}")
        print(f"  - View on block explorer: https://mempool.space/testnet/tx/{tx_hash}")

        time_taken = time.timestamp() - datetime.datetime.now().timestamp()
        print(f"  - Time taken: {time_taken:.2f} seconds")
    except Exception as e:
        print(f"\nAn unexpected error occurred during transaction creation: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
