import { readFile } from "fs/promises";
import { join } from "path";
import protobuf from "protobufjs";
import { fileURLToPath } from "url";
import Input from "./crypto/Input.js";
import Output, { protocolAddressToBase58 } from "./crypto/Output.js";
import ReadBuffer from './crypto/ReadBuffer.js';
import Tx from "./crypto/Tx.js";
import { bytesToHex } from './crypto/utils.js';
import WriteBuffer from './crypto/WriteBuffer.js';

const { ceil } = Math;


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

const messagesProtobuf = await protobuf.load(join(protobufsPath, "messages.proto"));
const signatureRequestProto = messagesProtobuf.lookupType('SignatureRequest');
const settlementRequestProto = messagesProtobuf.lookupType('SettlementRequest');


export function encodeTokenized(actionCode, message, production) {
    let writer = new WriteBuffer();
    writer.writeUInt8(OP_FALSE);
    writer.writeUInt8(OP_RETURN);
    writer.writePushData(new Uint8Array([0xbd, 0x01]));
    writer.writePushNumber(1);
    writer.writePushData(new TextEncoder().encode(production ? "TKN" : "test.TKN"));
    writer.writePushNumber(3);
    writer.writePushData(new Uint8Array([0]));
    writer.writePushData(new TextEncoder().encode(actionCode));
    writer.writePushData(actionLookup.get(actionCode)?.encode(message).finish());
    return writer.toBytes();
}

function decodeTokenizedPayload(actionCodeBuffer, payload) {
    let actionCode = new TextDecoder().decode(actionCodeBuffer);

    let actionType = actionLookup.get(actionCode);
    let message = actionType && actionType.toObject(actionType.decode(payload), { defaults: true });

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

export function computeTransferFees(transfer, feeRate) {
    // Estimate fees by constructing partially completed examples of expected on chain messages.
    // The aim is to over-estimate to avoid rejections due to insufficient funding
    // Example rejection message: Insufficient Transaction Fee Funding: 2019/2020: Insufficient Value
    // see in TX 3dbda19bf8e152736455531033ddb7399ea066423127bb6fa3bd25be4c419db2

    // Settlement T2 response message is sent in response to the supplied T1 transfer request
    let settlement = {
        Instruments: transfer.Instruments.map(
            ({ ContractIndex, InstrumentType, InstrumentCode, InstrumentSenders, InstrumentReceivers }) =>
            ({
                ContractIndex,
                InstrumentType,
                InstrumentCode,
                Settlements: [
                    ...InstrumentReceivers.map(() => ({
                        Index: 127,
                        Quantity: 2 ** 32,
                    })),
                    ...InstrumentSenders.map(() => ({
                        Index: 127,
                        Quantity: 2 ** 32,
                    }))
                ],
            })

        )
    };

    // The sending and receiving addresses need to be notified of new balances:
    let dustOutputAddresses = transfer.Instruments.flatMap(({ InstrumentSenders, InstrumentReceivers }) =>
        [
            ...InstrumentSenders.map(({ Index }) => null),
            ...InstrumentReceivers.map(({ Address }) => protocolAddressToBase58(Address))
        ]
    );

    let settlementTx = new Tx();
    // Signatures from the contract agents:
    settlementTx.inputs.push(...transfer.Instruments.map(({ ContractIndex }) => Input.p2pkh({}, 2 ** 32)))
    // Notifying the addresses holding tokens:
    settlementTx.outputs.push(...dustOutputAddresses.map(address => Output.p2pkh(address, 1)));
    // Funding to contract operators:
    settlementTx.outputs.push(...transfer.Instruments.map(() => Output.p2pkh(null, 2 ** 32)));
    let settlementOutput = Output.tokenized("T2", settlement);
    settlementTx.outputs.push(settlementOutput);
    // Change address:
    settlementTx.outputs.push(Output.p2pkh(null, 2 ** 32));

    let settlementTxBytes = settlementTx.toBytes();
    let settlementFee = ceil(settlementTxBytes.length * feeRate + dustOutputAddresses.length);

    // A settlement request is sent from the first contract agent to the second
    // and then along the chain of contract agents.
    // Each settlement and signature request would be different,
    // but here we calculate the largest one:
    let settlementRequestTx = new Tx();
    // Sending contract agent:
    settlementRequestTx.inputs.push(Input.p2pkh({}, 2 ** 32));
    // Receiving contract agent:
    settlementRequestTx.outputs.push(Output.p2pkh(null, 2 ** 32));
    settlementRequestTx.outputs.push(Output.tokenized("M1", {
        SenderIndexes: [0],
        ReceiverIndexes: [0],
        MessageCode: 1003,
        MessagePayload: settlementRequestProto.encode({
            Timestamp: Date.now() * 1e6,
            TransferTxId: new Uint8Array(32),
            ContractFees: [{
                Address: new Uint8Array(21),
                Quantity: 2 ** 32,
            }],
            Settlement: settlementOutput.script
        }).finish()
    }));

    // A signature request is sent back along the chain collecting signatures
    let signatureRequestTx = new Tx();
    // Sending contract agent:
    signatureRequestTx.inputs.push(Input.p2pkh({}, 2 ** 32));
    // Receiving contract agent:
    signatureRequestTx.outputs.push(Output.p2pkh(null, 2 ** 32));
    signatureRequestTx.outputs.push(Output.tokenized("M1", {
        SenderIndexes: [0],
        ReceiverIndexes: [0],
        MessageCode: 1002,
        MessagePayload: signatureRequestProto.encode({
            Timestamp: Date.now() * 1e6,
            Payload: settlementTxBytes
        }).finish()
    }));

    let signatureRequestTxBytes = signatureRequestTx.toBytes();
    let signatureRequestFee = signatureRequestTxBytes.length * feeRate;


    let settlementRequestTxBytes = settlementRequestTx.toBytes();
    let settlementRequestFee = settlementRequestTxBytes.length * feeRate;

    let boomerangCount = transfer.Instruments.length - 1;
    let boomerangFee = ceil(boomerangCount * (signatureRequestFee + settlementRequestFee));

    return [settlementFee, boomerangFee];
}

