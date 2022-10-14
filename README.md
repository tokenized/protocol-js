# Tokenized protocol in JS

This is a library, command line application and example code for interacting with the Tokenized Protocol in JavaScript.

## Library

```js
import {
  decodeTokenized,
  encodeTokenized,
  computeTransferFees,
} from "@tokenized/protocol-js";
```

- **decodeTokenized** takes a Uint8Array (eg a Node Buffer) and returns
  a structure contaning the decoded Tokenized action.

- **encodeTokenized** takes an action code and an action and returns the encoded action.

- **computeTransferFees** takes a transfer (T1) action and computes the smart contract fee.
  It returns an array of [settlementFee, boomerangFee] where:
  - settlementFee which should be added to the contract fee sent to the first smart contract address
  - boomerangFee should be sent in a separate output to the first smart contract address.
    The boomerangFee only applies to transfers with multiple smart contracts.

For example, send and receive tokens:

```js
import {
  decodeTokenized,
  encodeTokenized,
  base58AddressToProtocolAddress,
  jsonPrettyPrint,
  computeTransferFees,
} from "@tokenized/protocol-js";

const transfer = {
  Instruments: [
    {
      InstrumentType: "CHP",
      InstrumentCode: Buffer.from(
        "6aa85187fc5536a0c6c8bd165b0245d33f34573f",
        "hex"
      ),
      InstrumentSenders: [{ Quantity: 1, Index: 0 }],
      InstrumentReceivers: [
        {
          Address: base58AddressToProtocolAddress(
            "1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a"
          ),
          Quantity: 1,
        },
      ],
    },
  ],
};

const encoded = encodeTokenized("T1", transfer);

console.log(jsonPrettyPrint(decodeTokenized(encoded)), null, 4);

let smartContractFeeRate = 0.05;

let [settlementFee, boomerangFee] = computeTransferFees(
  transfer,
  smartContractFeeRate
);
console.log("Settlement fee", settlementFee, "boomerang fee", boomerangFee);
```

Addresses are traditionally formatted in Base58.
To represent them in binary form the functions `base58AddressToProtocolAddress` and `protocolAddressToBase58`
are exported:

```js
import {
  base58AddressToProtocolAddress,
  protocolAddressToBase58,
} from "@tokenized/protocol-js";

console.log(
  Buffer.from(
    base58AddressToProtocolAddress("1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a")
  ).toString("hex")
);
console.log(
  protocolAddressToBase58(
    Buffer.from("2086f0f5db0593576ee3737f75eb7dcaf8d08a8c91", "hex")
  )
);
```

## CLI

If running from checkout:

```
node ./cli.js
```

If installed globally:

```
protocol-js
```

```
protocol-js get 0d45da0f1eabeba2b383a09133f82d8b9fb0c7cbbd9d8ede626c45718df6660f
Get a transaction by hash from WhatsOnChain and decode it

protocol-js transactions 1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a
Get all transactions for an address from WhatsOnChain and decode them

protocol-js key private.key m/1/2
Make a private key if it does not exist and print the address of a BIP-32 derivation the key

protocol-js transfer private.key m/1/1/1 m/1/1/2 1 1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a
protocol-js transfer <private key file> <bsv path> <token path> <token quantity> <target address>
Transfer tokens from one address using bsv funding from another to a target address

protocol-js fees 78934b50a28b465319cdc61fbe960d6b5c69c9683cc35c13d1558f3014581276
Re-compute the fees (settlement, contract and boomerang) for a broadcast transaction
```

## Example code

See [cli.js](./cli.js) for usage examples
