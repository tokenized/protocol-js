import { Buffer } from 'buffer';
import { verify } from '@noble/secp256k1';
import {
  bytesToHex,
  hexToBytes,
  numberToBytes,
  bytesToNumber,
  padBytes,
} from './utils.js';

export default class Signature {
  constructor(value) {
    if (value) {
      if (typeof value === 'string' || value instanceof String) {
        this.fromString(value);
      } else if (Buffer.isBuffer(value)) {
        this.bytes = Uint8Array.from(value);
      } else if (value?.constructor?.name === 'ArrayBuffer') {
        this.bytes = new Uint8Array(value);
      } else if (value instanceof Uint8Array) {
        this.bytes = value;
      } else {
        throw new TypeError(
          `Must provide a string or buffer to deserialize a Signature: ${typeof value}`,
        );
      }
    }
  }

  static fromRS(r, s) {
    var result = new Signature();
    result.r = r;
    result.s = s;
    return result;
  }

  fromString(str) {
    this.bytes = new Uint8Array(hexToBytes(str));
  }

  toString() {
    this.calcBytes();
    return bytesToHex(this.bytes);
  }

  verify(publicKey, msgHash) {
    this.calcValue();
    this.calcBytes();
    if (this.r === 0n || this.s === 0n) {
      return false;
    }

    return verify(this.bytes, msgHash.toBytes(), publicKey.point());
  }

  toBytes() {
    this.calcBytes();
    return this.bytes;
  }

  calcBytes() {
    if (this.bytes && this.bytes.byteLength > 0) {
      return;
    }

    let rBytes = numberToBytes(this.r);
    let sBytes = numberToBytes(this.s);

    // Trim leading zero bytes
    let zeroBytes = 0;
    while (rBytes[zeroBytes] === 0x00) {
      zeroBytes += 1;
    }
    if (zeroBytes > 0) {
      rBytes = rBytes.subarray(zeroBytes);
    }

    let rlen = rBytes.byteLength;

    zeroBytes = 0;
    while (sBytes[zeroBytes] === 0x00) {
      zeroBytes += 1;
    }
    if (zeroBytes > 0) {
      sBytes = sBytes.subarray(zeroBytes);
    }

    let slen = sBytes.byteLength;

    let size = 6 + rBytes.byteLength + sBytes.byteLength;

    if (rBytes[0] >= 0x80) {
      rlen += 1;
      size += 1;
    }
    if (sBytes[0] >= 0x80) {
      slen += 1;
      size += 1;
    }

    this.bytes = new Uint8Array(size);

    // Header byte
    this.bytes[0] = 0x30;

    // Length
    this.bytes[1] = size - 2; // exclude header byte and length byte

    // R header byte
    let offset = 2;
    this.bytes[offset] = 0x02;
    offset += 1;

    // R length
    this.bytes[offset] = rlen;
    offset += 1;

    // R leading byte (prepend zero byte if first bit is 1)
    if (rBytes[0] >= 0x80) {
      this.bytes[offset] = 0x00;
      offset += 1;
    }

    // R value
    this.bytes.set(rBytes, offset);
    offset += rBytes.byteLength;

    // S header byte
    this.bytes[offset] = 0x02;
    offset += 1;

    // S length
    this.bytes[offset] = slen;
    offset += 1;

    // S leading byte (prepend zero byte if first bit is 1)
    if (sBytes[0] >= 0x80) {
      this.bytes[offset] = 0x00;
      offset += 1;
    }

    // S value
    this.bytes.set(sBytes, offset);
    offset += sBytes.byteLength;
  }

  calcValue() {
    if (typeof this.r === 'bigint') {
      return;
    }

    if (!this.bytes || !(this.bytes instanceof Uint8Array)) {
      throw new Error(`Signature bytes is wrong type ${typeof this.bytes}`);
    }

    if (!this.bytes || this.bytes.byteLength === 0) {
      throw new Error('Missing Signature value');
    }

    if (this.bytes[0] !== 0x30) {
      throw new Error(`Invalid Signature header byte: ${this.bytes[0]}`);
    }

    const length = this.bytes[1];
    if (length !== this.bytes.byteLength - 2) {
      throw new Error(
        `Invalid Signature length byte: ${this.bytes[1]} (should be ${
          this.bytes.byteLength - 1
        })`,
      );
    }

    let offset = 2;
    if (this.bytes[offset] !== 0x02) {
      throw new Error(`Invalid Signature r header byte: ${this.bytes[offset]}`);
    }
    offset += 1;

    const rLen = this.bytes[offset];
    offset += 1;

    if (rLen > length) {
      throw new Error(`Invalid Signature r length byte: ${rLen}`);
    }

    this.r = bytesToNumber(
      padBytes(this.bytes.slice(offset, offset + rLen), 32),
    );
    offset += rLen;

    if (this.bytes[offset] !== 0x02) {
      throw new Error(`Invalid Signature s header byte: ${this.bytes[offset]}`);
    }
    offset += 1;

    const sLen = this.bytes[offset];
    offset += 1;

    if (sLen > length) {
      throw new Error(`Invalid Signature s length byte: ${sLen}`);
    }

    this.s = bytesToNumber(
      padBytes(this.bytes.slice(offset, offset + sLen), 32),
    );
    offset += sLen;
  }
}
