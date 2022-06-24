import * as secp from "@noble/secp256k1";
import { readFile, writeFile } from "fs/promises";
import XKey from "./crypto/XKey.js";

export async function loadKey(privateKeyFile, path) {
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
