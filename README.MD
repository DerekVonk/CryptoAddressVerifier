# Crypto Address Validator

## Validation Levels

This script checks the validity of crypto addresses, verifies if they've been used on the blockchain, and matches two addresses against each other (if provided).

## Supported Crypto Address Formats

Currently, this script supports the following crypto address formats:
- Ethereum (ETH)
- Bitcoin (BTC)
- Cardano (ADA)

## Structure

The script consists of a `main()` function that performs the address validation, matching, and usage checks. It uses command-line arguments to provide addresses and network information. The script relies on three main functions:
- `is_same_address(address_a, address_b)`: Checks if two addresses match each other.
- `is_valid_address(address, network)`: Validates the format of the given address based on the specified network.
- `is_used_address(address, network)`: Checks if the address has been used on the blockchain.

## Usage

1. Run the script using the command line:

```bash
python cav.py <address_a> [-ab <address_b>] -n <network>
```


- `<address_a>`: The primary address to be validated.
- `-ab <address_b>` (optional): The second address to be matched against the first.
- `-n <network>`: The network the addresses are associated with (ETH, BTC, ADA).

2. The script performs the following checks:
- If two addresses are provided (`-ab` flag), it checks if they match.
- It validates the format of both addresses using the specified network's rules.
- If address_b is provided and matches, it checks if address_b has been used on the blockchain and prints the balance.
- If only address_a is provided, it validates its format and checks if it has been used on the blockchain.

## Disclaimer

This script is provided for educational and informational purposes only. Always verify transactions and addresses through trusted sources before making any financial decisions.

I borrowed / modified code from these projects:

Base58 decoding: https://github.com/keis/base58
Bech32 Validation: http://bit.ly/2Eaw40N

Please test thoroughly before using this in a production environment. 
There are no warranties, guarantees, or strings attached when using this software

## Future Work

- Expand the list of supported crypto address formats.
- Enhance error handling and informative messages for users.
- Provide additional features, such as checking transaction history and balances.
- Offer more advanced validation checks for addresses.
- Implement support for more networks and cryptocurrencies.

