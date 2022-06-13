import { join } from "path";
import fetch from 'node-fetch';
import { readFile, writeFile, mkdir } from "fs/promises";
import { hexToBytes } from "./crypto/utils.js";

// https://developers.whatsonchain.com/

export async function getTransaction(txid) {
    await mkdir("tx-cache", { recursive: true });
    let filePath = join("tx-cache", txid);
    let transactionBytes;
    try {
        transactionBytes = await readFile(filePath);
        //console.log("Loaded from cache", txid);
    } catch (e) {
        //console.log("Downloading", txid);
        transactionBytes = hexToBytes(await (await fetch(`https://api.whatsonchain.com/v1/bsv/main/tx/${encodeURIComponent(txid)}/hex`)).text());
        await writeFile(filePath, transactionBytes);
    }
    return transactionBytes;
}


export async function broadcastTransaction(network, transactionHex) {
    console.log(await (await fetch(`https://api.whatsonchain.com/v1/bsv/${encodeURIComponent(network)}/tx/raw`, { method: "POST", body: JSON.stringify({ txhex: transactionHex }) })).text());
}


export async function getAddressHistory(address) {
    return await (await fetch(`https://api.whatsonchain.com/v1/bsv/main/address/${encodeURIComponent(address)}/history`)).json();
}
