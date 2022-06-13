import { createHash } from "node:crypto";
import { bytesAreEqual } from "./utils.js";

const sha256 = v => createHash('sha256').update(v).digest();
const ripemd160 = v => createHash('ripemd160').update(v).digest();

let alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function publicKeyHashToAddress(input) {
    // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    let pk = new Uint8Array([0, ...input]);
    let checksum = sha256(sha256(pk)).slice(0, 4);
    return bufferToBase58(new Uint8Array([...pk, ...checksum]));
}

export function addressToPublicKeyHash(address) {
    let buffer = base58ToBuffer(address);
    let checksum = sha256(sha256(buffer.slice(0, -4))).slice(0, 4);
    if (!bytesAreEqual(buffer.slice(-4), checksum)) {
        throw new Error("Checksum invalid");
    }
    if (buffer[0] != '0') {
        throw new Error("Not mainnet address");
    }
    return buffer.slice(1, -4);
}



export function bufferToBase58(input) {
    // https://en.bitcoin.it/wiki/Base58Check_encoding
    let results = [];
    let value = input.reduce((result, v)  => (result << 8n) + BigInt(v), 0n);

    while (value) {
        results.push(alphabet[value % 58n]);
        value = value / 58n;
    }

    for (let i = 0; input[i] == 0; i++) {
        results.push('1');
    }

    return results.reverse().join("");
}

export function base58ToBuffer(input) {
    // https://en.bitcoin.it/wiki/Base58Check_encoding
    
    let results = [];

    let values = [...input].map(char => alphabet.indexOf(char));

    let invalidCharacterIndex = values.findIndex(v => v < 0);
    if (invalidCharacterIndex >= 0) {
        throw new Error(`Character not base58 [${input[invalidCharacterIndex]}]`);
    }

    let value = values.reduce((result, v)  => (result * 58n) + BigInt(v), 0n);

    while (value) {
        results.push(Number(value % 256n));
        value = value / 256n;
    }

    for (let i = 0; input[i] == '1'; i++) {
        results.push(0);
    }

    return new Uint8Array(results.reverse());
}

export function publicKeyToAddress(publicKey) {
    return publicKeyHashToAddress(ripemd160(sha256(publicKey)));
}



//console.log(publicKeyToAddress(Buffer.from("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", "hex")));
//1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs

//console.log(Buffer.from(addressToPublicKeyHash("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs")).toString("hex"));
//f54a5851e9372b87810a8e60cdd2e7cfd80b6e31