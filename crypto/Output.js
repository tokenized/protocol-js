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

const assets = JSON.parse(await readFile(join(protobufsPath, "assets.json")));
const assetsProtobuf = await protobuf.load(join(protobufsPath, "assets.proto"));

const assetTypeLookup = new Map(assets.messages.map(({ code, name }) =>
    [code, assetsProtobuf.lookupType(`assets.${name}`)]
));

export function contractAddressToBase58(input) {
  let type = input[0];
  if (type != 0x20) {
      throw "Not a public key hash address";
  }
  return publicKeyHashToAddress(input.slice(1));
}

export function base58AddressToContractAddress(address) {
  return new Uint8Array([0x20, ...addressToPublicKeyHash(address)]);
}

function jsonTransform(value) {
  if (value instanceof Uint8Array && value.length == 21 && value[0] == 0x20) {
    return contractAddressToBase58(value);
  }
  if (value instanceof Array) {
    return value.map(jsonTransform);
  }
  if (value instanceof Uint8Array) {
    return `0x${bytesToHex(value)}`;
  }
  if (value instanceof Object) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, jsonTransform(v)]));
  }
  return value;
}

function decodeTokenized(actionCodeBuffer, payload) {
  let actionCode = new TextDecoder().decode(actionCodeBuffer);

  let message = actionLookup.get(actionCode)?.decode(payload);
  
  let instrument = assetTypeLookup.get(message?.AssetType)?.decode(message?.InstrumentPayload);

  let content = message?.MessagePayload && new TextDecoder().decode(message?.MessagePayload);

  return {
    actionCode,
    message,
    asset: instrument,
    content
  }
}


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

  static tokenized(actionCode, message) {
    let writer = new WriteBuffer();
    writer.writeUInt8(OP_FALSE);
    writer.writeUInt8(OP_RETURN);
    writer.writePushData(new Uint8Array([0xbd, 0x01]));
    writer.writePushNumber(1);
    writer.writePushData(new TextEncoder().encode("test.TKN"));
    writer.writePushNumber(3);
    writer.writePushData(new Uint8Array([0]));
    writer.writePushData(new TextEncoder().encode(actionCode));
    writer.writePushData(actionLookup.get(actionCode)?.encode(message).finish());
    return new Output(writer.toBytes(), 0n);
  }

  get payload() {
    try {
      let read = new ReadBuffer(this.script);

      let initial = read.readUInt8();

      if (initial == OP_DUP && read.readUInt8() == OP_HASH160) {
        const hash = read.readPushData();
        if (hash.byteLength == 20 && read.readUInt8() == OP_EQUALVERIFY && read.readUInt8() == OP_CHECKSIG) {
          return { p2pkh: publicKeyHashToAddress(hash) };
        }
      }

      if (initial == OP_FALSE && read.readUInt8() == OP_RETURN) {
        const envelopeType = read.readPushData();
        if (bytesToHex(envelopeType) == 'bd01' && read.readPushNumber() == 1) {
          // https://tsc.bitcoinassociation.net/standards/envelope-specification/
          const protocol = new TextDecoder().decode(read.readPushData());
          if (protocol == "test.TKN" || protocol == "TKN") {
            let [version, typeCode, payloadProtobuf] = new Array(read.readPushNumber()).fill().map(() => read.readPushData());
            if (version.byteLength == 0 || bytesToHex(version) == '00') {
              return decodeTokenized(typeCode, payloadProtobuf);
            }
          }
        }

        if (bytesToHex(envelopeType) == 'bd00') {
          const protocol = new TextDecoder().decode(read.readPushData());
          if (protocol == "test.TKN" || protocol == "TKN") {
            let tokenizedEnvelope = Envelope.decode(new Uint8Array(read.readPushData()));
            return decodeTokenized(tokenizedEnvelope.Identifier, read.readPushData());
          }
        }
      }
    } catch (e) {
      console.log(e);
      return {error: `${e}`};
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
    const { value, payload, spent } = this;
    if (payload?.error) {
      return `${value} ! ${payload.error}`;
    }
    if (payload?.p2pkh) {
      return `${value} -> ${payload.p2pkh} ${spent !== undefined ? (spent ? "SPENT" : "UNSPENT") : ''}`;
    }
    if (payload?.actionCode) {
      return `${value}: ${payload.actionCode}\n${JSON.stringify(jsonTransform(payload), null, 4)}`
    }
    return `${this.value}`;
  }
}
