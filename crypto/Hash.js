import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  bytesToHex,
  hexToBytes,
  padBytes,
  numberToBytes,
  bytesToNumber,
} from './utils.js';

export default class Hash {
  constructor(value) {
    if (value) {
      if (typeof value === 'bigint') {
        this.value = value;
      } else if (typeof value === 'string' || value instanceof String) {
        this.fromString(value);
      } else if (value?.constructor?.name === 'ArrayBuffer') {
        this.bytes = new Uint8Array(value);
        this.bytes = padBytes(this.bytes, 32);
      } else if (value instanceof Uint8Array) {
        this.bytes = value;
        this.bytes = padBytes(this.bytes, 32);
      } else if (Buffer.isBuffer(value)) {
        this.bytes = Uint8Array.from(value);
        this.bytes = padBytes(this.bytes, 32);
      } else {
        throw new TypeError(
          `Must provide a bigint, string, or buffer to create a Hash: ${typeof value}`,
        );
      }
    }
  }

  fromString(str) {
    this.value = null;
    this.bytes = new Uint8Array(hexToBytes(str));
    this.bytes.reverse();
    this.bytes = padBytes(this.bytes, 32);
  }

  toString() {
    this.calcBytes();
    const rBytes = new Uint8Array(this.bytes.byteLength);
    rBytes.set(this.bytes);
    rBytes.reverse();
    return bytesToHex(rBytes);
  }

  fromBytes(bytes) {
    this.value = null;
    if (bytes?.constructor?.name === 'ArrayBuffer') {
      this.bytes = new Uint8Array(bytes);
      this.bytes = padBytes(this.bytes, 32);
    } else if (bytes instanceof Uint8Array) {
      this.bytes = bytes;
      this.bytes = padBytes(this.bytes, 32);
    } else {
      throw new TypeError(`Wrong Hash bytes type: ${typeof bytes}`);
    }
  }

  toBytes() {
    this.calcBytes();
    return this.bytes;
  }

  toNumber() {
    this.calcValue();
    return this.value;
  }

  calcValue() {
    if (this.value && typeof value === 'bigint') {
      return;
    }

    if (!this.bytes || !(this.bytes instanceof Uint8Array)) {
      throw new TypeError(`Hash bytes is wrong type ${typeof this.bytes}`);
    }

    if (this.bytes.byteLength !== 32) {
      throw new Error(`Hash wrong byte length ${this.bytes.byteLength}`);
    }

    this.value = bytesToNumber(this.bytes);
  }

  calcBytes() {
    if (this.bytes && this.bytes.byteLength === 32) {
      return;
    }

    if (!this.value || !(typeof value === 'bigint')) {
      throw new TypeError(`Hash value is wrong type ${typeof this.value}`);
    }

    this.bytes = numberToBytes(this.value);
    this.bytes = padBytes(this.bytes, 32);
  }
}

export async function sha256(data) {
  if (typeof window == 'object' && 'crypto' in window) {
    // Use Web Crypto API for native hash in browser
    const buffer = await window.crypto.subtle.digest('SHA-256', data);
    return new Hash(buffer);
  }
  // Otherwise use Node Crypto library
  // (provided in browsers by crypto-browserify)
  const bytes = Uint8Array.from(
    createHash('sha256').update(Buffer.from(data)).digest(),
  );
  return new Hash(bytes.buffer);
}

export function sha256sha256Sync(data) {
  // Use Node Crypto library
  // (provided in browsers by crypto-browserify)
  let bytes = createHash('sha256').update(Buffer.from(data)).digest();
  bytes = Uint8Array.from(createHash('sha256').update(bytes).digest());
  return new Hash(bytes.buffer);
}

export async function sha512(data) {
  if (typeof window == 'object' && 'crypto' in window) {
    // Use Web Crypto API for native hash in browser
    const buffer = await window.crypto.subtle.digest('SHA-512', data);
    return buffer;
  }
  // Otherwise use Node Crypto library
  // (provided in browsers by crypto-browserify)
  const bytes = Uint8Array.from(
    createHash('sha512').update(Buffer.from(data)).digest(),
  );
  return bytes.buffer;
}

export async function ripemd160(data) {
  // Use Node Crypto library
  // (provided in browsers by crypto-browserify)
  const bytes = Uint8Array.from(
    createHash('ripemd160').update(Buffer.from(data)).digest(),
  );
  return bytes;
}

export async function sha256sha256(buf) {
  const first = await sha256(buf);
  return await sha256(first.toBytes());
}

export async function ripemd160sha256(buf) {
  const first = await sha256(buf);
  return await ripemd160(first.toBytes().buffer);
}

async function hmac(hashFunction, blocksize, data, key) {
  // http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  // http://tools.ietf.org/html/rfc4868#section-2

  if (key.length > blocksize) {
    key = await hashFunction(key);
  } else if (key < blocksize) {
    var fill = new Uint8Array(blocksize);
    fill.fill(0);
    fill.set(key);
    key = fill;
  }

  var oKey = new Uint8Array(blocksize);
  oKey.fill(0x5c);

  var iKey = new Uint8Array(blocksize);
  iKey.fill(0x36);

  var oKeyPad = new Uint8Array(blocksize);
  var iKeyPad = new Uint8Array(blocksize);
  for (var i = 0; i < blocksize; i += 1) {
    oKeyPad[i] = oKey[i] ^ key[i];
    iKeyPad[i] = iKey[i] ^ key[i];
  }

  const concat1 = concatBytes(iKeyPad, data);
  const hash1 = new Uint8Array(await hashFunction(concat1));
  const concat2 = concatBytes(oKeyPad, hash1);
  const result = await hashFunction(concat2);
  return result;
}

function concatBytes(bytes1, bytes2) {
  const result = new Uint8Array(bytes1.byteLength + bytes2.byteLength);
  result.set(bytes1);
  result.set(bytes2, bytes1.byteLength);
  return result;
}

export async function sha256HMAC(data, key) {
  const bytes = await hmac(sha256, 64, data, key);
  return new Hash(bytes);
}

export async function sha512HMAC(data, key) {
  return await hmac(sha512, 128, data, key);
}
