import assert from "assert";

// WriteBuffer creates a Buffer from a series of sequential writes.
export default class WriteBuffer {
  constructor() {
    this.buffer = new ArrayBuffer(512);
    this.length = 0;
  }

  append(size, callback) {
    if (this.length + size > this.buffer.byteLength) {
      let newBuffer = new ArrayBuffer(this.buffer.byteLength * 2);
      new Uint8Array(newBuffer).set(new Uint8Array(this.buffer));
      this.buffer = newBuffer;
    }
    callback(this.buffer, this.length);
    this.length += size;
  }

  // write writes the contents of a buffer.
  writeBytes(data) {
    assert(ArrayBuffer.isView(data));
    this.append(data.byteLength, (buffer, offset) => new Uint8Array(buffer).set(data, offset));
  }

  // writeUInt8 writes a 8 bit unsigned integer.
  writeUInt8(value) {
    this.append(1, (buffer, offset) => new DataView(buffer).setUint8(offset, value));
  }

  // writeUInt16LE writes a 16 bit unsigned integer in little endian format.
  writeUInt16LE(value) {
    this.append(2, (buffer, offset) => new DataView(buffer).setUint16(offset, value, true));
  }

  // writeUInt32LE writes a 32 bit unsigned integer in little endian format.
  writeUInt32LE(value) {
    this.append(4, (buffer, offset) => new DataView(buffer).setUint32(offset, value, true));

  }

  // writeUInt32BE writes a 32 bit unsigned integer in big endian format.
  writeUInt32BE(value) {
    this.append(4, (buffer, offset) => new DataView(buffer).setUint32(offset, value, false));
  }

  // writeInt32LE writes a 32 bit signed integer in little endian format.
  writeInt32LE(value) {
    this.append(4, (buffer, offset) => new DataView(buffer).setInt32(offset, value, true));
  }

  // writeVarIntNum writes a Bitcoin P2P encoding variable sized integer.
  writeVarIntNum(value) {
    if (value < 0) {
      throw new Error('WriteBuffer Var Int negative');
    } else if (value < 0xfd) {
      this.writeUInt8(value);
    } else if (value <= 0xffff) {
      this.writeUInt8(0xfd);
      this.writeUInt16LE(value);
    } else if (value <= 0xffffffff) {
      this.writeUInt8(0xfe);
      this.writeUInt32LE(value);
    } else {
      throw new Error('WriteBuffer Var Int over 32 bits');
    }
  }

  // writePushData writes a Bitcoin script push data. It precedes the data with a variable size.
  writePushData(bytes) {
    assert(ArrayBuffer.isView(bytes));
    if (bytes.byteLength <= 0x4b) {
      // Max single byte push data size
      this.writeUInt8(bytes.byteLength);
    } else if (bytes.byteLength <= 0xff) {
      this.writeUInt8(0x4c); // OP_PUSH_DATA_1
      this.writeUInt8(bytes.byteLength);
    } else if (bytes.byteLength <= 0xffff) {
      this.writeUInt8(0x4d); // OP_PUSH_DATA_2
      this.writeUInt16LE(bytes.byteLength);
    } else if (bytes.byteLength <= 0xffffffff) {
      this.writeUInt8(0x4e); // OP_PUSH_DATA_4
      this.writeUInt32LE(bytes.byteLength);
    } else {
      throw new Error('WriteBuffer.writePushData data write size over 32 bits');
    }

    this.writeBytes(bytes);
  }

  writePushNumber(number) {
    if (number >= -1 && number <= 0x10) {
      this.writeUInt8(number + 0x50);
    } else {
      throw new Error("Push number not implemented for numbers outside -1 .. 16")
    }
  }

  // toBytes returns a single Uint8Array containing all of the data written.
  toBytes() {
    return new Uint8Array(this.buffer.slice(0, this.length));
  }
}
