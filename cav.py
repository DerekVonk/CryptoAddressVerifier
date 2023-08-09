import argparse
import hashlib
import json
import requests
from eip55 import test
from web3 import Web3
from decouple import config

ETHER_SCAN_API_KEY = config('ETHER_SCAN_API_KEY')

def is_valid_ethereum_address(address):
    """Returns True if the address is a valid Ethereum address, False otherwise."""
    if test(address) is None:
        return True
    return False


def is_valid_bitcoin_address(address):
    """Returns True if the address is a valid Bitcoin address, False otherwise."""

    if len(address) != 26:
        return False

    address_without_prefix = address[2:]

    checksum = address[0:2]
    sha256_hash = hashlib.sha256(address_without_prefix.encode())
    double_sha256_hash = hashlib.sha256(sha256_hash.digest()).hexdigest()[:4]

    if checksum != double_sha256_hash:
        return False

    return True


def is_valid_cardano_address(address):
    """Returns True if the address is a valid Cardano address, False otherwise."""

    if len(address) != 36:
        return False

    prefix = address[0:2]
    if prefix != "addr":
        return False

    address_without_prefix = address[2:]

    checksum = address[-8:]
    address_without_checksum = address[:-8]

    sha256_hash = hashlib.sha256(address_without_checksum.encode())
    double_sha256_hash = hashlib.sha256(sha256_hash.digest()).hexdigest()[:8]

    if checksum != double_sha256_hash:
        return False

    return True


def is_same_address(address_a, address_b):
    """Returns True if the two addresses are the same, False otherwise."""

    return address_a == address_b


def is_valid_address(address, network):
    """Returns True if the address is valid for the specified network, False otherwise."""

    if network == "ETH":
        return is_valid_ethereum_address(address)
    elif network == "BTC":
        return is_valid_bitcoin_address(address)
    elif network == "ADA":
        return is_valid_cardano_address(address)
    else:
        print("Invalid network specified.")
        return False


def is_non_zero_ethereum_address(address):
    """Returns True if the address has been used before, False otherwise."""

    url = ("https://api.etherscan.io/api"
           "?module=account"
           "&action=balance"
           "&tag=latest"
           "&address={}"
           "&apikey={}").format(address, ETHER_SCAN_API_KEY)
    response = requests.get(url)
    response.raise_for_status()

    data = json.loads(response.content)
    if data['status'] == '1':
        amount = data['result']
        return Web3.from_wei(int(amount), 'ether')
    else:
        print('Etherscan API returned error: {}'.format(data['result']))

    return False


def is_used_bitcoin_address(address):
    """Returns True if the address has been used before, False otherwise."""

    url = "https://blockchair.com/bitcoin/address/{}".format(address)
    response = requests.get(url)

    if response.status_code == 200:
        data = json.loads(response.content)

        if "balance" in data:
            return True

    return False


def is_used_cardano_address(address):
    """Returns True if the address has been used before, False otherwise."""

    url = "https://cardanoscan.io/address/{}".format(address)
    response = requests.get(url)

    if response.status_code == 200:
        data = json.loads(response.content)

        if "totalReceived" in data:
            return True

    return False


def is_used_address(address, network):
    """Returns True if the address has been used before, False otherwise."""

    if network == "ETH":
        return is_non_zero_ethereum_address(address)
    elif network == "BTC":
        return is_used_bitcoin_address(address)
    elif network == "ADA":
        return is_used_cardano_address(address)
    else:
        print("Invalid network specified.")
        return False


def main():
    """The main function."""

    parser = argparse.ArgumentParser(description="Check if crypto addresses are valid on the blockchain, "
                                                 "if they've been used and if 2 addresses are given, if they match.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("address_a", help="The address(es) to verify")
    parser.add_argument('-ab', '--address_b', help="The second address to match against the first", required=False)
    parser.add_argument('-n', '--network', help="The network the addresses are on. (ETH, BTC, ADA)")

    args = parser.parse_args()

    address_a = args.address_a
    address_b = args.address_b
    network = args.network

    # We're checking both addresses for a match, validity and if address_b has value
    if address_b:
        if is_same_address(address_a, address_b):
            print("The addresses MATCH.")
        else:
            print("The addresses DO NOT MATCH!")
            return

        if not is_valid_address(address_a, network):
            print("address is Invalid '{}'.".format(address_a))
            return

        amount = is_used_address(address_b, network)
        if amount:
            print("Second Address '{}'\n\thas non-zero amount of {} {}".format(address_b, amount, network))

    # We're checking if the address is valid
    else:
        if not is_valid_address(address_a, network):
            print("address is Invalid '{}'.".format(address_a))
            return


if __name__ == "__main__":
    main()
