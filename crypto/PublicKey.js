import { Buffer } from 'buffer';
import { Point } from '@noble/secp256k1';
import {
  bytesToHex,
  padBytes,
  numberToBytes,
  hexToBytes,
} from './utils.js';

export default class PublicKey {
  constructor(value) {
    if (value) {
      if (value instanceof Point) {
        this.value = value;
      } else if (typeof value === 'string' || value instanceof String) {
        this.fromString(value);
      } else if (Buffer.isBuffer(value)) {
        this.bytes = Uint8Array.from(value);
      } else if (value?.constructor?.name === 'ArrayBuffer') {
        this.bytes = new Uint8Array(value);
      } else if (value instanceof Uint8Array) {
        this.bytes = value;
      } else {
        throw new TypeError(
          `Must provide a string or buffer to deserialize a PublicKey: ${typeof value}`,
        );
      }
    }
  }

  isValid() {
    this.calcValue();
    return this.value.x !== 0n && this.value.y !== 0n;
  }

  fromString(str) {
    const bytes = new Uint8Array(hexToBytes(str));
    this.fromBytes(bytes);
  }

  toString() {
    this.calcBytes();
    return bytesToHex(this.bytes);
  }

  fromBytes(bytes) {
    this.value = null;
    this.bytes = bytes;
  }

  toBytes() {
    this.calcBytes();
    return this.bytes;
  }

  point() {
    this.calcValue();
    return this.value;
  }

  calcValue() {
    if (this.value && this.value instanceof Point) {
      return;
    }

    if (!this.bytes || !(this.bytes instanceof Uint8Array)) {
      throw new Error(`PublicKey bytes is wrong type ${typeof this.bytes}`);
    }

    if (this.bytes.byteLength !== 33) {
      throw new Error(`PublicKey wrong byte length ${this.bytes.byteLength}`);
    }

    this.value = Point.fromCompressedHex(this.bytes);
  }

  calcBytes() {
    if (this.bytes && this.bytes.byteLength > 0) {
      return;
    }

    if (!this.value || !(this.value instanceof Point)) {
      throw new Error(`PublicKey value is wrong type ${typeof this.value}`);
    }

    this.bytes = new Uint8Array(33);

    if (this.value.y & 1n) {
      this.bytes[0] = 0x03;
    } else {
      this.bytes[0] = 0x02;
    }

    const xBytes = padBytes(numberToBytes(this.value.x), 32);
    this.bytes.set(xBytes, 1);
  }
}

export function addPublicKeys(key1, key2) {
  return new PublicKey(key1.point().add(key2.point()));
}
