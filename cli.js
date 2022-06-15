#!/usr/bin/env node
const usage = `
protocol-js get 0d45da0f1eabeba2b383a09133f82d8b9fb0c7cbbd9d8ede626c45718df6660f
Get a transaction by hash from WhatsOnChain and decode it

protocol-js transactions 1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a
Get all transactions for an address from WhatsOnChain and decode them

protocol-js key private.key m/1/2
Make a private key if it does not exist and print the address of a BIP-32 derivation the key

protocol-js transfer private.key m/1/1/1 m/1/1/2 1 1DJWCvgTFQBxYiDnVX3edG1A9kEidzLs9a
protocol-js transfer <private key file> <bsv path> <token path> <token quantity> <target address>
Transfer tokens from one address using bsv funding from another to a target address
`;

if (Number(process.versions.openssl.split(".")[0]) >= 3) {
    console.log("openssl 3 does not provide ripemd160 required for bitcoin hashing");
    console.log("Suggest using Node 16 or lower");
    process.exit(1);
}


import * as secp from "@noble/secp256k1";
import { readFile, writeFile } from "fs/promises";
import { addressToPublicKeyHash, publicKeyToAddress } from "./crypto/address.js";
import Hash from "./crypto/Hash.js";
import Input from "./crypto/Input.js";
import Output, { base58AddressToContractAddress } from "./crypto/Output.js";
import Tx from "./crypto/Tx.js";
import { bytesToHex } from "./crypto/utils.js";
import { broadcastTransaction, getAddressHistory, getTransaction } from "./network.js";
import XKey from "./crypto/XKey.js";
import fetch from "node-fetch";

const { round } = Math;

const feeRate = 0.5;

const CONTRACT_OPERATOR_SERVICE_TYPE = 3;


async function get(txid) {
    let transaction = await getTransaction(txid);

    console.log("%s", new Tx(transaction));
}



async function loadKey(privateKeyFile, path) {
    let seed;

    try {
        seed = await readFile(privateKeyFile);
    } catch (e) {
        if (e.code == 'ENOENT') {
            seed = secp.utils.randomPrivateKey();
            await writeFile(privateKeyFile, seed);
        } else {
            throw e;
        }
    }

    let xkey = await XKey.fromSeed(seed);

    return await xkey.derive(path);
}

async function key(privateKeyFile, path = "m") {
    let derivedKey = await loadKey(privateKeyFile, path);
    console.log(publicKeyToAddress(derivedKey.publicKey().toBytes()));
}

async function transactions(address) {
    for (let tx of await getAddressTransactions(address)) {
        console.log(`ID: ${tx.hash} ; height: ${tx.height}`);
        console.log("%s", tx);
        console.log("".padStart(process.stdout.columns, "-"));
    }
}

function annotateSpentOutputs(txs, address) {
    for (let tx of txs) {
        for (let [index, output] of tx.outputs.map((output, index) => [index, output])) {

            if (output.payload?.p2pkh == address) {
                output.spent = !!txs.find(({ inputs }) => inputs.find(input => input.hash == tx.hash && input.index == index));
            }
        }
    }

    return txs;
}

async function getAddressTransactions(address) {
    let txs = [];

    for (let { tx_hash: hash, height } of await getAddressHistory(address)) {
        let tx = new Tx(await getTransaction(hash));
        tx.hash = hash;
        tx.height = height;
        txs.push(tx);
    }

    annotateSpentOutputs(txs, address);

    return txs;
}

async function getOutput(address, filter) {
    for (let tx of await getAddressTransactions(address)) {
        let hash = tx.hash;
        let index = tx.outputs.findIndex(filter);
        if (index >= 0) {
            let output = tx.outputs[index];
            return { hash, index, tx, output };
        }
    }
}


async function getAction(address, code) {
    return await getOutput(address, ({ payload }) => payload?.actionCode == code);
}

async function getBSV(address, minValue) {
    return await getOutput(address, ({ payload, value, spent }) => !spent && payload?.p2pkh == address && value >= minValue);
}


// 1P4FaWQofBNhaR1bVPYxRg31N8zw5dkTtq is the Tokenized smart contract operator address
async function create(contractOperatorAddress) {
    const operatorContract = (await getAction(contractOperatorAddress, "C2"));
    if (!operatorContract) {
        throw new Error("Operator contract not found");
    }
    const { output: { payload: { message: { Services } } } } = operatorContract;
    const url = Services.find(({ Type }) => Type == CONTRACT_OPERATOR_SERVICE_TYPE).URL;
    console.log((await (await fetch(new URL('/new_contract', url)))).json());
}

async function transfer(privateKeyFile, bsvPath, tokenPath, quantity, targetAddress) {
    if (!targetAddress) {
        console.log(usage);
        return 1;
    }
    const bsvXKey = await loadKey(privateKeyFile, bsvPath);
    const tokenXKey = (await loadKey(privateKeyFile, tokenPath));

    let tx = new Tx();

    const contractAgentFee = 3000n;
    const maximumMinerFee = 500n;

    let tokenAddress = publicKeyToAddress(tokenXKey.publicKey().toBytes());
    let tokens = await getAction(tokenAddress, "T2");
    let bsvAddress = publicKeyToAddress(bsvXKey.publicKey().toBytes());
    let requiredValue = contractAgentFee + maximumMinerFee;
    let bsv = await getBSV(bsvAddress, requiredValue);

    if (!tokens) {
        throw new Error("Tokens not found at address");
    }

    if (!bsv) {
        throw new Error(`Insufficient funds, required: ${requiredValue}`);
    }

    let contractAgentAddress = tokens.tx.inputs[0].payload.p2pkh;
    let instrument = tokens.output.payload.message.Instruments[0];

    let tokenUtxo = await getBSV(tokenAddress, 0);
    if (!tokenUtxo < 0) {
        throw new Error("Unable to find token utxo");
    }

    tx.inputs.push(Input.p2pkh(tokenUtxo, tokenXKey.key()));
    tx.inputs.push(Input.p2pkh(bsv, bsvXKey.key()));

    tx.outputs.push(Output.p2pkh(contractAgentAddress, contractAgentFee));
    tx.outputs.push(Output.tokenized("T1", {
        Instruments: [
            {
                InstrumentType: instrument.InstrumentType,
                InstrumentCode: instrument.InstrumentCode,
                InstrumentSenders: [{ Quantity: quantity }],
                InstrumentReceivers: [{
                    Address: base58AddressToContractAddress(targetAddress),
                    Quantity: quantity
                }]
            }
        ]
    }));
    let changeOutput = Output.p2pkh(bsvAddress, 0);

    tx.outputs.push(changeOutput);
    let fee = BigInt(round(feeRate * tx.size()));
    changeOutput.value = bsv.output.value - contractAgentFee - fee;

    for (let [{ spendingOutput, key }, index] of tx.inputs.map((i, index) => [i, index])) {
        await tx.signP2PKHInput(key, index, spendingOutput.script, spendingOutput.value);
    }

    console.log("%s", tx);

    console.log(bytesToHex(tx.toBytes()));

    console.log("Transaction ID:", await broadcastTransaction("main", bytesToHex(tx.toBytes())));
}

// currently only sends bsv:
async function send(privateKeyFile, path, inputs, quantity, targetAddress, changeAddress) {
    const key = (await loadKey(privateKeyFile, path)).key();

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
        await tx.signP2PKHInput(key, index, spendingOutput.script, spendingOutput.value);
    }

    console.log("%s", tx);

    console.log(bytesToHex(tx.toBytes()));

    await broadcastTransaction("main", bytesToHex(tx.toBytes()));
}

const commands = { get, key, send, transactions, create, transfer };

function help() {
    console.log(usage);
}

async function main(commandName, ...args) {
    await (commands[commandName] || help)(...args);
}

await main(...process.argv.slice(2)).catch(console.error).then((code = 1) => process.exitCode = code);
