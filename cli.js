#!/usr/bin/env node
const usage = `
protocol-js get 0d45da0f1eabeba2b383a09133f82d8b9fb0c7cbbd9d8ede626c45718df6660f
Get a transaction by hash from WhatsOnChain and decode it

protocol-js transactions 1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a
Get all transactions for an address from WhatsOnChain and decode them

protocol-js key private.key
Make a private key if it does not exist and print the address of the key
`;


import * as secp from "@noble/secp256k1";
import { readFile, writeFile } from "fs/promises";
import { publicKeyToAddress } from "./crypto/address.js";
import Hash from "./crypto/Hash.js";
import { Output, Input, Tx } from "@tokenized/protocol-js";
import { bytesToHex } from "./crypto/utils.js";
import { broadcastTransaction, getAddressHistory, getTransaction } from "./network.js";

const { round } = Math;

const feeRate = 0.1;


async function get(txid) {
    let transaction = await getTransaction(txid);

    console.log("%s", new Tx(transaction));
}

async function key(privateKeyFile) {
    let privateKey;

    try {
        privateKey = await readFile(privateKeyFile);
    } catch (e) {
        if (e.code == 'ENOENT') {
            privateKey = secp.utils.randomPrivateKey();
            await writeFile(privateKeyFile, privateKey);
        }
    }

    const publicKey = secp.getPublicKey(privateKey);

    console.log(publicKeyToAddress(publicKey));
}

async function address(privateKeyFile) {
    const privateKey = await readFile(privateKeyFile);
    const publicKey = secp.getPublicKey(privateKey);

    console.log(publicKeyToAddress(publicKey));
}

async function transactions(address) {
    for (let { tx_hash, height } of await getAddressHistory(address)) {
        console.log(`ID: ${tx_hash} ; height: ${height}`);
        console.log("%s", new Tx(await getTransaction(tx_hash)));
        console.log("".padStart(process.stdout.columns, "-"));
    }
}

// currently only sends bsv:
async function send(privateKeyFile, inputs, quantity, targetAddress, changeAddress) {
    const privateKey = await readFile(privateKeyFile);

    let tx = new Tx();
    let inputValue = 0;

    let spendingOutputs = await Promise.all(
        inputs.split(",")
            .map(i => i.split(":"))
            .map(async ([txId, number]) => {
                let spendingOutput = new Tx(await getTransaction(txId)).outputs[number];
                tx.inputs.push(new Input(new Hash(txId), number, new Uint8Array(71 + 32)));
                inputValue += Number(spendingOutput.value);
                return spendingOutput;
            })
    );

    tx.outputs.push(Output.p2pkh(targetAddress, quantity));
    let changeOutput = Output.p2pkh(changeAddress, 0);
    tx.outputs.push(changeOutput);
    let fee = round(feeRate * tx.size());
    changeOutput.value = inputValue - quantity - fee;

    for (let [spendingOutput, index] of spendingOutputs.map((output, index) => [output, index])) {
        await tx.signP2PKHInput(privateKey, index, spendingOutput.script, spendingOutput.value, 0);
    }

    console.log("%s", tx);

    console.log(bytesToHex(tx.toBytes()));

    await broadcastTransaction("main", bytesToHex(tx.toBytes()));
}

const commands = { get, key, send, transactions };

function help() {
    console.log(usage);
}

async function main(commandName, ...args) {
    await (commands[commandName] || help)(...args);
}

await main(...process.argv.slice(2));