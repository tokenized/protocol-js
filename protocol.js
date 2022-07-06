import { readFile } from "fs/promises";
import { join } from "path";
import protobuf from "protobufjs";
import { fileURLToPath } from "url";
import ReadBuffer from './crypto/ReadBuffer.js';
import { bytesToHex } from './crypto/utils.js';
import WriteBuffer from './crypto/WriteBuffer.js';


const OP_FALSE = 0x00;
const OP_RETURN = 0x6a;

const protobufsPath = fileURLToPath(new URL("./protobufs", import.meta.url));

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


export function encodeTokenized(actionCode, message) {
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
    return writer.toBytes();
}

function decodeTokenizedPayload(actionCodeBuffer, payload) {
    let actionCode = new TextDecoder().decode(actionCodeBuffer);

    let actionType = actionLookup.get(actionCode);
    let message = actionType && actionType.toObject(actionType.decode(payload), {defaults: true});

    let instrument = assetTypeLookup.get(message?.InstrumentType)?.decode(message?.InstrumentPayload);

    let content = message?.MessagePayload && new TextDecoder().decode(message?.MessagePayload);

    return {
        actionCode,
        message,
        instrument,
        content
    }
}

export function decodeTokenized(bytes) {
    let read = new ReadBuffer(bytes);

    let initial = read.readUInt8();

    if (initial == OP_FALSE && read.readUInt8() == OP_RETURN) {
        const envelopeType = read.readPushData();
        if (bytesToHex(envelopeType) == 'bd01' && read.readPushNumber() == 1) {
            // https://tsc.bitcoinassociation.net/standards/envelope-specification/
            // https://github.com/tokenized/envelope
            const protocol = new TextDecoder().decode(read.readPushData());
            if (protocol == "test.TKN" || protocol == "TKN") {
                let [version, typeCode, payloadProtobuf] = new Array(read.readPushNumber()).fill().map(() => read.readPushData());
                if (version.byteLength == 0 || bytesToHex(version) == '00') {
                    return decodeTokenizedPayload(typeCode, payloadProtobuf);
                }
            }
        }

        if (bytesToHex(envelopeType) == 'bd00') {
            const protocol = new TextDecoder().decode(read.readPushData());
            if (protocol == "test.TKN" || protocol == "TKN") {
                let tokenizedEnvelope = Envelope.decode(new Uint8Array(read.readPushData()));
                return decodeTokenizedPayload(tokenizedEnvelope.Identifier, read.readPushData());
            }
        }
    }   
}