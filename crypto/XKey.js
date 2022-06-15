import { Buffer } from 'buffer';
import bs58 from 'bs58';
import ReadBuffer from './ReadBuffer.js';
import WriteBuffer from './WriteBuffer.js';
import Key, { addPrivateKeys } from './Key.js';
import PublicKey, { addPublicKeys } from './PublicKey.js';
import { ripemd160sha256, sha512HMAC, sha256sha256Sync } from './Hash.js';
import {
  bytesAreEqual,
  bytesToHex,
  hexToBytes,
} from './utils.js';

export const Bip32Hardened = 0x80000000; // Hardened child index offset
export const Bip32PrivateVersion = 0x0488ade4;
export const Bip32PublicVersion = 0x0488b21e;

// XKey implements bip-0032 key derivation.
export default class XKey {
  constructor(value) {
    // bip-0032 data
    this.version = 0;
    this.depth = 0;
    this.fingerPrint = null;
    this.index = 0; // uint32
    this.chainCode = null;
    this.keyBytes = null;

    // cached values
    this.privKey = null;
    this.pubKey = null;

    if (value) {
      if (typeof value === 'string' || value instanceof String) {
        this.fromString(value);
      } else if (Buffer.isBuffer(value)) {
        this.fromBytes(Uint8Array.from(value));
      } else if (value?.constructor?.name === 'ArrayBuffer') {
        this.fromBytes(new Uint8Array(value));
      } else if (value instanceof Uint8Array) {
        this.fromBytes(value);
      } else {
        throw new TypeError(
          'Must provide a bigint, string, or buffer to create a XKey',
        );
      }
    } else {
      this.version = Bip32PrivateVersion;
      this.fingerPrint = new Uint8Array(4).fill(0);
      this.chainCode = new Uint8Array(32).fill(0);
      this.keyBytes = new Uint8Array(33).fill(0);
    }
  }

  static async fromSeed(value) {
    let bytes;
    if (Buffer.isBuffer(value)) {
      bytes = Uint8Array.from(value);
    } else if (value?.constructor?.name === 'ArrayBuffer') {
      bytes = new Uint8Array(value);
    } else if (value instanceof Uint8Array) {
      bytes = value;
    } else {
      throw new TypeError('Must provide Buffer to create XKey from seed');
    }

    if (bytes.byteLength < 16) {
      throw new Error('XKey: Need more than 128 bits of entropy');
    }
    if (bytes.byteLength > 64) {
      throw new Error('XKey: More than 512 bits of entropy is nonstandard');
    }

    // 'Bitcoin seed' to hex is "426974636f696e2073656564"
    const key = new Uint8Array(hexToBytes('426974636f696e2073656564'));
    const hash = await sha512HMAC(bytes, key);
    const hashBytes = new Uint8Array(hash);

    const result = new XKey();
    result.version = Bip32PrivateVersion;
    result.depth = 0; // zero depth for root key
    result.fingerPrint = new Uint8Array(4).fill(0); // zero fingerprint for root key
    result.index = 0; // zero index for root key
    result.chainCode = hashBytes.slice(32);
    result.keyBytes = new Uint8Array(33);
    result.keyBytes[0] = 0; // first byte means private key
    result.keyBytes.set(hashBytes.slice(0, 32), 1);
    return result;
  }

  fromString(str) {
    const bytes = new Uint8Array(bs58.decode(str));
    const check = bytes.slice(-4);
    const hash = sha256sha256Sync(bytes.slice(0, -4));
    const hashCheck = hash.toBytes().slice(0, 4);
    if (!bytesAreEqual(check, hashCheck)) {
      throw new Error(
        `checksum invalid : check ${bytesToHex(
          check,
        )}, hash ${bytesToHex(hashCheck)}`,
      );
    }

    this.fromBytes(bytes.slice(0, -4));
  }

  toString() {
    const bytes = this.toBytes();
    const hash = sha256sha256Sync(bytes);
    const check = hash.toBytes().slice(0, 4);
    const buf = new WriteBuffer();
    buf.writeBytes(bytes);
    buf.writeBytes(check);
    return bs58.encode(Buffer.from(buf.toBytes()));
  }

  fromBytes(bytes) {
    this.read(new ReadBuffer(bytes));
  }

  toBytes() {
    const buf = new WriteBuffer();
    this.writeBytes(buf);
    return buf.toBytes();
  }

  write(writeBuffer) {
    writeBuffer.writeUInt32BE(this.version);
    writeBuffer.writeUInt8(this.depth);
    writeBuffer.writeBytes(this.fingerPrint);
    writeBuffer.writeUInt32BE(this.index);
    writeBuffer.writeBytes(this.chainCode);
    writeBuffer.writeBytes(this.keyBytes);
  }

  read(readBuffer) {
    this.version = readBuffer.readUInt32BE();
    this.depth = readBuffer.readUInt8();
    this.fingerPrint = new Uint8Array(readBuffer.read(4));
    this.index = readBuffer.readUInt32BE();
    this.chainCode = new Uint8Array(readBuffer.read(32));
    this.keyBytes = new Uint8Array(readBuffer.read(33));

    if (this.version == Bip32PrivateVersion) {
      if (this.keyBytes[0] !== 0x00) {
        throw new Error('XKey: xprv key doesn’t start with zero');
      }
    } else if (this.version == Bip32PublicVersion) {
      if (this.keyBytes[0] !== 0x02 && this.keyBytes[0] !== 0x03) {
        throw new Error(
          `XKey: xpub key invalid first byte ${this.keyBytes[0]}`,
        );
      }
    } else {
      throw new Error(`invalid XKey version : 0x${this.version.toString(16)}`);
    }
  }

  isPrivate() {
    return this.keyBytes[0] === 0x00;
  }

  toPublic() {
    if (!this.isPrivate()) {
      return this; // already public
    }

    const result = new XKey();
    result.version = Bip32PublicVersion;
    result.depth = this.depth;
    result.fingerPrint = this.fingerPrint.slice(); // make copy
    result.index = this.index;
    result.chainCode = this.chainCode.slice(); // make copy
    result.pubKey = this.publicKey();
    result.keyBytes = result.pubKey.toBytes();

    return result;
  }

  key() {
    if (this.privKey) {
      return this.privKey;
    }

    if (!this.isPrivate()) {
      throw new Error("Can't get key for public XKey");
    }

    this.privKey = new Key(this.keyBytes.slice(1));
    return this.privKey;
  }

  publicKey() {
    if (this.pubKey) {
      return this.pubKey;
    }

    if (this.isPrivate()) {
      this.pubKey = this.key().publicKey();
    } else {
      this.pubKey = new PublicKey(this.keyBytes);
    }

    return this.pubKey;
  }

  // derive a child from a index path string
  async derive(path) {
    const pathIndexes = path.split('/');
    let result = this;
    for (let i = 0; i < pathIndexes.length; i += 1) {
      if (i !== 0 || pathIndexes[i] !== 'm') {
        // if indexes starts with "m" just skip it
        const index = stringToIndex(pathIndexes[i]);
        result = await result.deriveChild(index);
      }
    }

    return result;
  }

  // derive an immediate child from its index.
  async deriveChild(index) {
    if (index >= Bip32Hardened && !this.isPrivate()) {
      throw new Error("Can't derive hardened child from public extended key");
    }

    const result = new XKey();
    result.version = this.version;
    result.depth = this.depth + 1;
    result.index = index;

    // Calculate fingerprint. TODO this isn't needed for strict key derivation.
    let fingerPrint;
    if (this.isPrivate()) {
      fingerPrint = await ripemd160sha256(this.publicKey().toBytes());
    } else {
      fingerPrint = await ripemd160sha256(this.keyBytes);
    }
    result.fingerPrint = new Uint8Array(fingerPrint).slice(0, 4);

    // Calculate child
    const buf = new WriteBuffer();

    if (index >= Bip32Hardened) {
      // Hardened child
      // Write private key with leading zero
      buf.writeBytes(this.keyBytes);
    } else {
      // Write compressed public key
      if (this.isPrivate()) {
        buf.writeBytes(this.publicKey().toBytes());
      } else {
        buf.writeBytes(this.keyBytes);
      }
    }

    buf.writeUInt32BE(index);

    const data = new Uint8Array(buf.toBytes());
    const hashData = await sha512HMAC(data, this.chainCode);
    const sum = new Uint8Array(hashData);

    // Set chain code
    result.chainCode = sum.slice(32);

    // Calculate child
    if (this.isPrivate()) {
      result.privKey = addPrivateKeys(new Key(sum.slice(0, 32)), this.key());

      if (!result.privKey.isValid()) {
        throw new Error('XKey: derived key is invalid');
      }

      result.keyBytes = new Uint8Array(33);
      result.keyBytes[0] = 0; // private key starts with zero
      result.keyBytes.set(result.privKey.toBytes(), 1);
    } else {
      const iKey = new Key(sum.slice(0, 32));
      const iPublicKey = iKey.publicKey();
      result.pubKey = addPublicKeys(iPublicKey, this.publicKey());

      if (!result.pubKey.isValid()) {
        throw new Error('XKey: derived public key is invalid');
      }

      result.keyBytes = result.pubKey.toBytes();
    }

    return result;
  }
}

// eslint-disable-next-line no-unused-vars
function indexToString(index) {
  if (index > 0xffffffff) {
    throw new Error(`XKey: path index too high ${index}`);
  }
  if (index >= Bip32Hardened) {
    return (index - Bip32Hardened).toString() + "'";
  }
  return index.toString();
}

function stringToIndex(pathIndex) {
  if (pathIndex.length == 0) {
    throw new Error('XKey: empty path index');
  }

  if (pathIndex.slice(-1) == "'") {
    return parseInt(pathIndex.slice(0, -1), 10) + Bip32Hardened;
  }

  return parseInt(pathIndex, 10);
}
