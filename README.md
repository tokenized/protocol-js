# Tokenized protocol in JS

This is a library, command line application and example code for interacting with the Tokenized Protocol in JavaScript.

## Library

```js
import { Output, Input, Tx } from "@tokenized/protocol-js";
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

protocol-js key private.key
Make a private key if it does not exist and print the address of the key
```

## Example code
See [cli.js] for usage examples