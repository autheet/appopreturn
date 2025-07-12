import os
import hashlib
import sys
import traceback
from dotenv import load_dotenv
from firebase_functions import https_fn
from bit import PrivateKeyTestnet
from bitcoinlib.wallets import Wallet
from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction

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
    print(f"Address to fund: {key.address}")
    print(key.get_balance('btc'))
    print(key.balance)
    try:
        tx_hash = key.send(
            # outputs=[(key.address, 1, 'satoshi')],
            outputs=[],
            message=digest,
            combine=False
        )
        return tx_hash
    except Exception:
        # Keep traceback for debugging purposes, but no other printing.
        traceback.print_exc(file=sys.stderr)
        raise

def process_appopreturn_digest_to_blockchain_bitcoinlib(digest: str) -> str:
    """
    Creates and broadcasts a Bitcoin Testnet transaction with an OP_RETURN output using bitcoinlib.
    """
    private_key_wif = os.getenv("WALLET_PRIVATE_KEY")
    if not private_key_wif:
        raise ValueError("WALLET_PRIVATE_KEY environment variable not set.")

    key = Key(wif=private_key_wif, network='testnet')
    print(f"Address to fund: {key.address}")

    # Create a new transaction
    tx = Transaction(network='testnet')

    # Add the OP_RETURN output
    tx.add_op_return(digest.encode('utf-8'))

    # Get UTXOs for the address
    utxos = Wallet(private_key_wif).get_utxos()

    # Add an input from the UTXOs
    tx.add_input(utxos[0])

    # Add a change output if necessary
    change_address = key.address
    tx.add_change_output(change_address)

    # Sign the transaction
    tx.sign(key)

    # Broadcast the transaction
    tx.send()

    return tx.txid

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
        # print(process_appopreturn_digest_to_blockchain(digest=hex_digest))
        print(process_appopreturn_digest_to_blockchain_bitcoinlib(digest=hex_digest))
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
