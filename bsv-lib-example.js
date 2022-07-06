#!/usr/bin/env node
const usage = `
./bsv-lib-example.js private.key m/1 m/2 748bdc4c784a42cbc73004d197dc6615c88fdaca5cd6fdd02388585828191803:2 a49932537edec8af2e22bb606ec2ed3f9017d725ff862128b6f40481c3b8f0f9:3 a49932537edec8af2e22bb606ec2ed3f9017d725ff862128b6f40481c3b8f0f9:0 2 18UDGrRh8434Afv1D6EuT9Vy87oAabNmyy 1NnJfqgMsLbyCakfXECgJrJCmk288wF8FA
bsv-lib-example.js private.key bsv-derivation-path token-derivation-path bsvTx:out tokenTx:out dustTx:out quantity destination-address 
Transfer tokens using BSV library
`;

if (process.argv.length < 3) {
    console.log(usage);
    process.exit(1);
}

import { Tx, base58AddressToProtocolAddress } from "@tokenized/protocol-js";
import { bytesToHex } from "./crypto/utils.js";
import { broadcastTransaction, getTransaction } from "./network.js";
import { decodeTokenized, encodeTokenized } from "./protocol.js";
import { loadKey } from "./keys.js";

const feeRate = 0.5;
const dustAmount = 546;

const { default: bsv } = await import('bsv').catch(e => null);

async function getBSVTx(txid) {
    return new bsv.Tx().fromBr(new bsv.Br(await getTransaction(txid)));
}



async function transferTxBuilder(privateKeyFile, bsvPath, tokenPath, bsvInput, tokenInput, tokenDust, quantityString, targetAddress, changeAddress) {
    if (!bsv) throw "bsv library not found";
    let quantity = Number(quantityString);
    let [bsvTxId, bsvOutputIndex] = bsvInput.split(":").map((item, index) => index == 1 ? Number(item) : item);
    let [tokenTxId, tokenOutputIndex] = tokenInput.split(":").map((item, index) => index == 1 ? Number(item) : item);
    let [tokenDustTxId, tokenDustOutputIndex] = tokenDust.split(":").map((item, index) => index == 1 ? Number(item) : item);
    let bsvUtxo = (await getBSVTx(bsvTxId)).txOuts[bsvOutputIndex];
    let tokenUtxo = (await getBSVTx(tokenDustTxId)).txOuts[tokenDustOutputIndex];
    let tokenizedActionTx = await getBSVTx(tokenTxId);
    let tokenizedAction = decodeTokenized(tokenizedActionTx.txOuts[tokenOutputIndex].script.toBuffer());
    let contractAgentAddress = new bsv.Address().fromTxInScript(tokenizedActionTx.txIns[0].script);

    let instrument = tokenizedAction.message.Instruments[0];

    const txBuilder = new bsv.TxBuilder()
        .setFeePerKbNum(feeRate * 1000)
        .setDust(dustAmount)
        .sendDustChangeToFees(true);

    const contractAgentFee = 3000;

    txBuilder
        .outputToAddress(
            new bsv.Bn(contractAgentFee),
            contractAgentAddress
        );

    txBuilder
        .outputToScript(
            new bsv.Bn(0),
            new bsv.Script().fromBuffer(Buffer.from(encodeTokenized("T1", {
                Instruments: [
                    {
                        InstrumentType: instrument.InstrumentType,
                        InstrumentCode: instrument.InstrumentCode,
                        InstrumentSenders: [{
                            Quantity: quantity,
                            Index: 0
                        }],
                        InstrumentReceivers: [{
                            Address: base58AddressToProtocolAddress(targetAddress),
                            Quantity: quantity
                        }]
                    }
                ]
            })))
        );

    const bsvXKey = await loadKey(privateKeyFile, bsvPath);
    const tokenXKey = await loadKey(privateKeyFile, tokenPath);

    txBuilder.inputFromPubKeyHash(
        Buffer.from(tokenDustTxId, 'hex').reverse(),
        tokenDustOutputIndex,
        tokenUtxo,
    );

    txBuilder.inputFromPubKeyHash(
        Buffer.from(bsvTxId, 'hex').reverse(),
        bsvOutputIndex,
        bsvUtxo,
    );

    txBuilder.setChangeAddress(new bsv.Address().fromString(changeAddress));

    const tx = new Tx(txBuilder.build().tx.toBuffer());

    const bsvSpendingOutput = new Tx(await getTransaction(bsvTxId)).outputs[bsvOutputIndex];
    const tokenDustSpendingOutput = new Tx(await getTransaction(tokenDustTxId)).outputs[tokenDustOutputIndex];
    await tx.signP2PKHInput(tokenXKey.key(), 0, tokenDustSpendingOutput.script, tokenDustSpendingOutput.value);
    await tx.signP2PKHInput(bsvXKey.key(), 1, bsvSpendingOutput.script, bsvSpendingOutput.value);

    console.log(bytesToHex(tx.toBytes()));

    console.log("Transaction ID:", await broadcastTransaction("main", bytesToHex(tx.toBytes())));
}


await transferTxBuilder(...process.argv.slice(2)).catch(console.error).then((code = 1) => process.exitCode = code);
