import { Buffer } from 'node:buffer';
import ReadBuffer from './ReadBuffer.js';
import WriteBuffer from './WriteBuffer.js';
import Hash, { ripemd160sha256, ripemd160sha256sync } from './Hash.js';
import { publicKeyHashToAddress } from './address.js';

// Input is a Bitcoin input containing the hash and index of the UTXO being spent as well as a
//   unlocking script and sequence value.
export default class Input {
  constructor(hash, index, script, sequence = 0xffffffff) {
    this.hash = hash;
    this.index = index;
    this.script = script;
    this.sequence = sequence;
  }

  static p2pkh({hash, index, output}, key) {
    let input = new Input(new Hash(hash), index, new Uint8Array(106));
    input.spendingOutput = output;
    input.key = key;
    return input;
  }

  // fromString reads a hex string containing a serialized input.
  fromString(string) {
    this.fromReadBuffer(new ReadBuffer(string));
  }

  // fromReadBuffer reads a serialized input from a ReadBuffer.
  static fromReadBuffer(read) {
    const hash = new Hash(read.readBytes(32));
    const index = read.readUInt32LE();

    const sizeScript = read.readVarIntNum();
    const script = read.readBytes(sizeScript);

    const sequence = read.readUInt32LE();

    return new Input(hash, index, script, sequence);
  }

  // toBytes returns a Buffer containing the input serialized in binary format.
  toBytes() {
    const writeBuffer = new WriteBuffer();
    this.writeBytes(writeBuffer);
    return writeBuffer.toBytes();
  }

  // write writes the input into a WriteBuffer in binary format.
  write(writeBuffer) {
    writeBuffer.writeBytes(this.hash.toBytes());
    writeBuffer.writeUInt32LE(this.index);

    writeBuffer.writeVarIntNum(this.script.byteLength);
    writeBuffer.writeBytes(this.script);

    writeBuffer.writeUInt32LE(this.sequence);
  }

  get payload() {
    try {
      const read = new ReadBuffer(this.script);
      const signature = read.readPushData();
      const publicKey = read.readPushData();

      return { p2pkh: publicKeyHashToAddress(ripemd160sha256sync(publicKey)) };
    } catch (e) {
      // ignore parse script failure
      console.log(e);
    }
  }

  toString() {
    let { hash, index, payload } = this;
    return `${this.hash} #${this.index} ${payload?.p2pkh || ''}`;
  }
}
