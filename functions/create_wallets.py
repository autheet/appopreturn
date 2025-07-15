# First, make sure you have the 'bit' library installed:
# pip install bit

import os
from bit import PrivateKeyTestnet
from bit.network import get_fee


def create_and_save_wallets(count, filename="new_testnet_wallets.csv"):
    """
    Generates a specified number of new testnet wallets and saves them to a CSV file.

    Args:
        count (int): The number of wallets to create.
        filename (str): The name of the file to save the wallet details to.

    Returns:
        list: A list of tuples, where each tuple contains (address, wif).
    """
    print(f"\nCreating {count} new testnet wallets...")
    wallets = []
    with open(filename, 'w') as f:
        f.write("address,wif\n")  # CSV Header
        for i in range(count):
            key = PrivateKeyTestnet()
            address = key.address
            wif = key.to_wif()
            wallets.append((address, wif))
            f.write(f"{address},{wif}\n")
            print(f"  {i + 1:3d}. Address: {address}")

    print(f"\nSuccessfully saved {count} new wallets to '{filename}'.")
    return wallets


def distribute_funds(source_wif, wallets_to_fund):
    """
    Distributes half of the source wallet's balance to a list of new wallets.

    Args:
        source_wif (str): The Wallet Import Format (WIF) of the source wallet.
        wallets_to_fund (list): A list of tuples containing (address, wif).
    """
    try:
        source_wallet = PrivateKeyTestnet(source_wif)
    except ValueError as e:
        print(f"Error: Invalid private key provided. Please check your WIF. Details: {e}")
        return

    print(f"\nSource Wallet Address: {source_wallet.address}")

    # Get balance in satoshis
    balance_satoshi = int(source_wallet.get_balance('satoshi'))
    print(f"Source Wallet Balance: {source_wallet.get_balance('btc')} BTC ({balance_satoshi} satoshis)")

    if balance_satoshi == 0:
        print("\nError: Source wallet has no funds. Please fund it on a testnet faucet.")
        return

    # Calculate divider of the balance to distribute
    total_to_distribute = balance_satoshi // 4
    num_wallets = len(wallets_to_fund)

    if num_wallets == 0:
        print("\nError: No wallets to distribute funds to.")
        return

    amount_per_wallet = total_to_distribute // num_wallets

    # Bitcoin has a dust limit (transactions for tiny amounts are rejected)
    # 546 satoshis is a common dust limit.
    dust_limit = 546
    if amount_per_wallet < dust_limit:
        print(f"\nError: Calculated amount per wallet ({amount_per_wallet} satoshis) is below the dust limit.")
        print("You need more funds in the source wallet to make this distribution.")
        return

    print(f"\nTotal to distribute: {total_to_distribute} satoshis")
    print(f"Amount per wallet:   {amount_per_wallet} satoshis")

    # Prepare the transaction outputs
    outputs = []
    for address, _ in wallets_to_fund:
        outputs.append((address, amount_per_wallet, 'satoshi'))

    print("\nPreparing to send transaction...")

    try:
        # The 'bit' library automatically calculates the fee and subtracts it
        # from the total amount sent or the remaining change.
        tx_hash = source_wallet.send(outputs, fee=get_fee('fast'))
        print("\n✅ Transaction successfully broadcast!")
        print(f"Transaction ID: {tx_hash}")
        print(f"View it on a block explorer like: https://mempool.space/testnet/tx/{tx_hash}")

    except ValueError as e:
        # This exception is often raised for insufficient funds for the transaction + fee
        print(f"\n❌ Transaction Failed: {e}")
        print("This may be due to insufficient funds to cover the transaction amount plus the network fee.")
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")


if __name__ == '__main__':
    # --- IMPORTANT ---
    # Replace this with the private key (WIF) of your TESTNET wallet.
    # It MUST have funds from a testnet faucet.
    # DO NOT USE A MAINNET KEY.
    WALLET_PRIVATE_KEY = "cTxxxxxxxxxxxxxxx"  # <--- REPLACE THIS

    if "cTxxxx" in WALLET_PRIVATE_KEY:
        print("=" * 60)
        print("!! PLEASE REPLACE THE 'WALLET_PRIVATE_KEY' IN THE SCRIPT !!")
        print("=" * 60)
    else:
        NUMBER_OF_WALLETS = 10

        # 1. Create new wallets and save them to a file
        new_wallets = create_and_save_wallets(NUMBER_OF_WALLETS)

        # 2. Distribute funds from the source wallet to the new wallets
        distribute_funds(WALLET_PRIVATE_KEY, new_wallets)
