#!/usr/bin/env python3

import argparse
import hashlib
import json
from requests import get
from eip55 import validate
from web3 import Web3
from decouple import config
import base58
from pycoin.contrib import bech32m

ETHER_SCAN_API_KEY = config('ETHER_SCAN_API_KEY')


def is_valid_ethereum_address(address):
    """Returns True if the address is a valid Ethereum address, False otherwise."""

    return validate(address)


def is_valid_bitcoin_address(address):
    """Returns True if the address is a valid Bitcoin address, False otherwise."""

    if address[0] == "1":  # P2PKH Address
        return base58.b58decode_check(address)
    elif address[0] == "3":  # P2SH Address
        return base58.b58decode_check(address)
    elif address[:3] == "bc1":  # Bech32 Addresses (Segwit)
        return bech32m.bech32_decode(address)
    else:
        return False


def is_valid_cardano_address(address):
    """Returns True if the address is a valid Cardano address, False otherwise."""
    raise NotImplementedError("Not yet implemented")

    # if len(address) != 36:
    #     return False
    #
    # prefix = address[0:2]
    # if prefix != "addr":
    #     return False
    #
    # address_without_prefix = address[2:]
    #
    # checksum = address[-8:]
    # address_without_checksum = address[:-8]
    #
    # sha256_hash = hashlib.sha256(address_without_checksum.encode())
    # double_sha256_hash = hashlib.sha256(sha256_hash.digest()).hexdigest()[:8]
    #
    # if checksum != double_sha256_hash:
    #     return False
    #
    # return True


def is_same_address(address_a, address_b):
    """Returns True if the two addresses are the same, False otherwise."""

    return address_a.lower() == address_b.lower()


def is_valid_address(address):
    """Returns True if the address is valid for the specified network, False otherwise."""


def get_network_from_address(address):
    """Returns the network that the address runs on.

    Args:
      address: The cryptocurrency address.

    Returns:
      The network that the address runs on, or None if the address is invalid.
    """
    try:
        if is_valid_ethereum_address(address):
            return "ETH"
        elif is_valid_bitcoin_address(address):
            return "BTC"
        elif is_valid_cardano_address(address):
            return "ADA"
        else:
            return None
    except NotImplementedError:
        print("Validating this address is not yet implemented...")
        raise


def is_non_zero_ethereum_address(address):
    """Returns True if the address has been used before, False otherwise."""

    url = ("https://api.etherscan.io/api"
           "?module=account"
           "&action=balance"
           "&tag=latest"
           "&address={}"
           "&apikey={}").format(address, ETHER_SCAN_API_KEY)
    response = get(url)
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

    url = "https://chain.api.btc.com/v3/address/{}".format(address)
    response = get(url)
    response.raise_for_status()

    data = json.loads(response.content)
    amount = data['data']['balance']
    if amount:
        amount /= 100_000_000
        return amount

    return False


def is_used_cardano_address(address):
    """Returns True if the address has been used before, False otherwise."""

    raise NotImplementedError("Not yet implemented")

    #
    # url = "https://cardanoscan.io/address/{}".format(address)
    # response = get(url)
    #
    # if response.status_code == 200:
    #     data = json.loads(response.content)
    #
    #     if "totalReceived" in data:
    #         return True
    #
    # return False


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

    args = parser.parse_args()

    address_a = args.address_a
    address_b = args.address_b

    # get the network associated with the address and validate address
    try:
        network = get_network_from_address(address_a)
        if not network:
            print("address is Invalid '{}'.".format(address_a))
            return
    except NotImplementedError:
        return

    # We're checking both addresses for a match
    if address_b:
        if is_same_address(address_a, address_b):
            print("The addresses MATCH.")
        else:
            print("The addresses DO NOT MATCH!")
            return

    amount = is_used_address(address_a, network)
    if amount:
        print("Address has non-zero amount of {} {}".format(amount, network))
        return


if __name__ == "__main__":
    main()
