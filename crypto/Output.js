import assert from "assert";
import { readFile } from "fs/promises";
import { join } from "path";
import protobuf from "protobufjs";
import { fileURLToPath } from "url";
import { addressToPublicKeyHash, publicKeyHashToAddress } from './address.js';
import ReadBuffer from './ReadBuffer.js';
import { bytesToHex, bytesToNumber, numberToBytes, padBytesEnd } from './utils.js';
import WriteBuffer from './WriteBuffer.js';


const OP_FALSE = 0x00;
const OP_RETURN = 0x6a;
const OP_DUP = 0x76;
const OP_HASH160 = 0xa9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;

const protobufsPath = fileURLToPath(new URL("../protobufs", import.meta.url));

const envelope = await protobuf.load(join(protobufsPath, "envelope.proto"));
const Envelope = envelope.lookupType("protobuf.Envelope");

const actions = JSON.parse(await readFile(join(protobufsPath, "actions.json")));
const actionsProtobuf = await protobuf.load(join(protobufsPath, "actions.proto"));

const actionLookup = new Map(actions.messages.map(({ code, name }) =>
  [code, actionsProtobuf.lookupType(`actions.${name}`)]
));


// Output is a Bitcoin output containing a value and a locking script.
export default class Output {
  constructor(script, value) {
    assert(script.buffer instanceof ArrayBuffer);
    this.script = script;
    this.value = value;
  }

  static p2pkh(address, value) {
    let writer = new WriteBuffer();
    writer.writeUInt8(OP_DUP);
    writer.writeUInt8(OP_HASH160);
    writer.writePushData(addressToPublicKeyHash(address));
    writer.writeUInt8(OP_EQUALVERIFY);
    writer.writeUInt8(OP_CHECKSIG);
    return new Output(writer.toBytes(), value);
  }

  get payload() {
    try {
      let read = new ReadBuffer(this.script);

      let initial = read.readUInt8();

      if (initial == OP_DUP && read.readUInt8() == OP_HASH160) {
        const hash = read.readPushData();
        if (hash.byteLength == 20 && read.readUInt8() == OP_EQUALVERIFY && read.readUInt8() == OP_CHECKSIG) {
          return {P2PKH: publicKeyHashToAddress(hash)};
        }
      }

      if (initial == OP_FALSE && read.readUInt8() == OP_RETURN) {
        const envelopeType = read.readPushData();
        if (bytesToHex(envelopeType) == 'bd01' && read.readPushNumber() == 1) {
          // https://tsc.bitcoinassociation.net/standards/envelope-specification/
          const protocol = new TextDecoder().decode(read.readPushData());
          if (protocol == "test.TKN" || protocol == "TKN") {
            let [version, typeCode, payloadProtobuf] = new Array(read.readPushNumber()).fill().map(() => read.readPushData());
            if (bytesToHex(version) == '00') {
              const actionCode = new TextDecoder().decode(typeCode);

              return {
                actionCode,
                message: actionLookup.get(actionCode)?.decode(payloadProtobuf)
              }
            }

          }
        }

        if (bytesToHex(envelopeType) == 'bd00') {
          const protocol = new TextDecoder().decode(read.readPushData());
          if (protocol == "test.TKN" || protocol == "TKN") {
            let tokenizedEnvelope = Envelope.decode(new Uint8Array(read.readPushData()));

            const actionCode = new TextDecoder().decode(tokenizedEnvelope.Identifier);
            
            return {
              actionCode,
              message: actionLookup.get(actionCode)?.decode(read.readPushData())
            }
          }
        }
      }
    } catch (e) {
      console.log(e);
      // Ignore unparseable script
    }
  }

  
  
  // fromReadBuffer reads a serialized output from a ReadBuffer.
  static fromReadBuffer(read) {
    const b = new Uint8Array(read.readBytes(8));
    b.reverse();
    const value = bytesToNumber(b);

    const sizeScript = read.readVarIntNum();
    const script = read.readBytes(sizeScript);

    return new Output(script, value);
  }

  // toBytes returns a Buffer containing the output serialized in binary format.
  toBytes() {
    const writeBuffer = new WriteBuffer();
    this.write(writeBuffer);
    return writeBuffer.toBytes();
  }

  // write writes the output into a WriteBuffer in binary format.
  write(writeBuffer) {
    this.normalizeValue();

    
    const b = numberToBytes(this.value);
    b.reverse();
    const valueBytes = padBytesEnd(b, 8);
    writeBuffer.writeBytes(valueBytes);

    writeBuffer.writeVarIntNum(this.script.byteLength);
    writeBuffer.writeBytes(this.script);
  }

  normalizeValue() {
    if (typeof this.value === 'number') {
      this.value = BigInt(this.value);
      return;
    }
  }

  toString() {
    const {value, payload} = this;
    if (payload?.P2PKH) {
      return `${value} -> ${payload.P2PKH}`;
    }
    if (payload?.actionCode) {
      return `${value}: ${payload.actionCode}\n${JSON.stringify(payload.message, null, 4)}`
    }
    return `${this.value}`;
  }
}
