import { bytesToHex, formatOpcode } from './utils.js';

// ReadBuffer is a Buffer that can be read like a stream.
export default class ReadBuffer {
  constructor(bytes) {
    this.offset = 0;
    this.bytes = bytes;

    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    
  }

  toString() {
    return bytesToHex(this.bytes);
  }

  // read reads the specified number of bytes, returning them in an array buffer.
  readBytes(size) {
    if (this.offset + size > this.bytes.byteLength) {
      throw new Error(
        `ReadBuffer not enough data to read: ${this.offset} + ${size} > ${this.bytes.byteLength}`,
      );
    }
    const val = this.bytes.slice(this.offset, this.offset + size);
    this.offset += size;

    return val;
  }

  // readUInt8 reads an 8 bit unsigned integer.
  readUInt8() {
    const val = this.view.getUint8(this.offset);
    this.offset += 1;
    return val;
  }

  // readUInt16LE reads a 16 bit unsigned integer in little endian format.
  readUInt16LE() {
    const val = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return val;
  }

  // readUInt32LE reads a 32 bit unsigned integer in little endian format.
  readUInt32LE() {
    const val = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return val;
  }

  // readUInt32BE reads a 32 bit unsigned integer in big endian format.
  readUInt32BE() {
    const val = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }

  // readVarIntNum reads a Bitcoin P2P encoding variable sized integer.
  readVarIntNum() {
    const first = this.readUInt8();
    switch (first) {
      case 0xfd: // 16 bit integer
        return this.readUInt16LE();
      case 0xfe: // 32 bit integer
        return this.readUInt32LE();
      case 0xff: // 64 bit integer
        return this.readBytes(8);
      default:
        // 8 bit integer
        return first;
    }
  }

  // readPushData reads a Bitcoin script push data, returning it in a buffer.
  // The data is preceded with a variable size that is not included in the returned buffer data.
  // If the next item in the script is not a push data, then the integer value of the next op code
  //   is returned.
  readPushData() {
    const opcode = this.readUInt8();
    if (opcode <= 0x4b) {
      // Max single byte push data size
      return this.readBytes(opcode);
    }
    if (opcode === 0x4c) {
      // OP_PUSH_DATA_1
      const size = this.readUInt8();
      return this.readBytes(size);
    }
    if (opcode === 0x4d) {
      // OP_PUSH_DATA_2
      const size = this.readUInt16LE();
      return this.readBytes(size);
    }
    if (opcode === 0x4e) {
      // OP_PUSH_DATA_4
      const size = this.readUInt32LE();
      return this.readBytes(size);
    }

    throw new Error(`Not push data [${formatOpcode(opcode)}]`);
  }

  readPushNumber() {
    // https://en.bitcoin.it/wiki/Script
    const opcode = this.readUInt8();
    if (opcode == 0) {
      return 0;
    }

    if (opcode >= 0x4f && opcode <= 0x60) {
      return opcode - 0x50;
  }

    throw new Error(`Not push number [${formatOpcode(opcode)}]`);
  }
}
