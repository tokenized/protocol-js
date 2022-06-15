import { Buffer } from 'buffer';
import bs58 from 'bs58';
import { Point, sign, CURVE } from '@noble/secp256k1';
import WriteBuffer from './WriteBuffer.js';
import Signature from './Signature.js';
import PublicKey from './PublicKey.js';
import Hash, { sha256sha256Sync } from './Hash.js';
import {
  bytesAreEqual,
  bytesToNumber,
  numberToBytes,
  mod,
  padBytes,
} from './utils.js';

const signOptions = {
  recovered: false,
  canonical: true,
};

export default class Key {
  constructor(value) {
    if (value) {
      if (typeof value === 'bigint') {
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
          `Must provide a big int, string, or buffer to create a Key: ${typeof value}`,
        );
      }
    }
  }

  isValid() {
    this.calcValue();
    return 0n < this.value && this.value < CURVE.n;
  }

  fromString(str) {
    const bytes = new Uint8Array(bs58.decode(str));

    if (bytes[0] !== 0x80 && bytes[0] !== 0xef) {
      throw new Error(`Invalid Key type byte ${bytes[0]}`);
    }

    const check = bytes.slice(-4);
    const hash = sha256sha256Sync(bytes.slice(0, -4));
    const hashCheck = hash.toBytes().slice(0, 4);
    if (!bytesAreEqual(check, hashCheck)) {
      throw new Error('Key checksum invalid');
    }

    this.bytes = bytes.slice(1, -4);
    if (this.bytes.byteLength == 33) {
      this.bytes = this.bytes.slice(0, -1); // remove public key type byte
    }
  }

  toString() {
    const bytes = new Uint8Array(34);
    bytes[0] = 0x80;
    bytes.set(this.toBytes(), 1);
    bytes[33] = 0x01; // public key type

    const hash = sha256sha256Sync(bytes);
    const check = hash.toBytes().slice(0, 4);
    const buf = new WriteBuffer();
    buf.write(bytes);
    buf.write(check);
    return bs58.encode(Buffer.from(buf.toBytes()));
  }

  toBytes() {
    this.calcBytes();
    return this.bytes;
  }

  number() {
    this.calcValue();
    return this.value;
  }

  publicKey() {
    this.calcValue();
    // console.time('Key.publicKey (Point.BASE.multiply)');
    const point = Point.BASE.multiply(this.value);
    // console.timeEnd('Key.publicKey (Point.BASE.multiply)');
    const key = new PublicKey(point);
    return key;
  }

  async sign(msgHash) {
    if (!msgHash || !(msgHash instanceof Hash))
      throw new Error(`Message hash wrong type ${typeof msgHash}`);

    this.calcBytes();
    const sigBytes = await sign(msgHash.toBytes(), this.bytes, signOptions);
    return new Signature(sigBytes);
  }

  calcValue() {
    if (this.value && typeof this.value === 'bigint' && this.value > 0) {
      return;
    }

    if (!this.bytes || !(this.bytes instanceof Uint8Array)) {
      throw new Error(`Key bytes is wrong type ${typeof this.bytes}`);
    }

    if (this.bytes.byteLength === 0) {
      throw new Error('Key bytes is empty');
    }

    this.value = bytesToNumber(this.bytes);
  }

  calcBytes() {
    if (this.bytes && this.bytes.byteLength > 0) {
      return;
    }

    if (!this.value || !(typeof this.value === 'bigint')) {
      throw new Error(`Key value is wrong type ${typeof this.value}`);
    }

    this.bytes = padBytes(numberToBytes(this.value), 32);
  }
}

export function addPrivateKeys(key1, key2) {
  const sum = key1.number() + key2.number();
  const m = mod(sum, CURVE.n);
  return new Key(m);
}
