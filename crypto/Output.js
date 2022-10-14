import assert from "assert";
import { readFile } from "fs/promises";
import { join } from "path";
import protobuf from "protobufjs";
import { fileURLToPath } from "url";
import { decodeTokenized, encodeTokenized } from "../protocol.js";
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

export function protocolAddressToBase58(input) {
  let type = input[0];
  if (type != 0x20) {
    throw new Error("Not a public key hash address");
  }
  return publicKeyHashToAddress(input.slice(1));
}

export function base58AddressToProtocolAddress(address) {
  return new Uint8Array([0x20, ...addressToPublicKeyHash(address)]);
}

function jsonTransform(value) {
  if (value instanceof Uint8Array && value.length == 21 && value[0] == 0x20) {
    return `address:${protocolAddressToBase58(value)}`;
  }
  if (value instanceof Array) {
    return value.map(jsonTransform);
  }
  if (value instanceof Uint8Array) {
    return `bytes:${bytesToHex(value)}`;
  }
  if (value?.constructor?.isLong?.(value)) {
    return value.toNumber();
  }
  if (value instanceof Object) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, jsonTransform(v)]));
  }

  return value;
}

export function jsonPrettyPrint(value) {
  return JSON.stringify(jsonTransform(value), null, 4);
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
    writer.writePushData(address ? addressToPublicKeyHash(address) : new Uint8Array(20));
    writer.writeUInt8(OP_EQUALVERIFY);
    writer.writeUInt8(OP_CHECKSIG);
    return new Output(writer.toBytes(), value);
  }

  static tokenized(actionCode, message) {
    return new Output(encodeTokenized(actionCode, message), 0n);
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

      return decodeTokenized(this.script);

    } catch (e) {
      //console.log(e);
      return { error: `${e}` };
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
      return `${value}: ${payload.actionCode}\n${jsonPrettyPrint(payload)}`
    }
    return `${this.value}`;
  }
}
