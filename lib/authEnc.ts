import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import {Rand, Prime} from "@safeheron/crypto-rand"
const P256 = elliptic.ec('p256')
import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"
import {ECIES} from "./ecies"
import * as assert from "assert"

export namespace AuthEnc {
    /**
     * Authenticate and encrypt the data.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param plain
     * @returns Promise<string> A string encoded in base64
     */
    export async function _encrypt(localAuthPriv: BN, remoteAuthPub: any, plain: string| number[]| CryptoJSBytes) : Promise<string>{
        let plainBytes = null
        if (typeof plain === 'string') {
            plainBytes = cryptoJS.enc.Utf8.parse(plain)
        } else if (plain instanceof Array) {
            plainBytes = Hex.toCryptoJSBytes(Hex.fromBytes(plain))
        } else {
            // CryptoJSBytes
            plainBytes = plain
        }

        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(plainBytes)
        let digest = sha256.finalize()
        let hash = new BN(digest.toString(cryptoJS.enc.Hex), 16)
        //let ecdsa = new elliptic.ec(P256)
        let priv = P256.keyFromPrivate(localAuthPriv)
        let signature = P256.sign(hash, priv)
        let signatureBytes = cryptoJS.enc.Hex.parse(Hex.pad64(signature.r.toString(16)))
        signatureBytes.concat(cryptoJS.enc.Hex.parse(Hex.pad64(signature.s.toString(16))))

        let sig_plain = plainBytes.concat(signatureBytes)

        let cypherBytes = await ECIES.encryptCryptoJSBytes(remoteAuthPub, sig_plain)

        return UrlBase64.fromCryptoJSBytes(cypherBytes)
    }
    /**
     * Verify the signatures and decrypt the data.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param cypher = Base64(cypherBytes + signature(64 byte))
     * @returns [boolean, CryptoJSBytes]
     */
    export function _decrypt(localAuthPriv: BN, remoteAuthPub: any, cypher: string): [boolean, CryptoJSBytes] {
        let cypherBytes = UrlBase64.toCryptoJSBytes(cypher)
        //Decrypt
        let sig_plain = ECIES.decryptCryptoJSBytes(localAuthPriv, cypherBytes)
        let sig_plain_hex = cryptoJS.enc.Hex.stringify(sig_plain)

        //signature(64 byte)
        assert(sig_plain_hex.length > 128)

        let r = new BN(sig_plain_hex.substring(sig_plain_hex.length - 128, sig_plain_hex.length - 64), 16)
        let s = new BN(sig_plain_hex.substring(sig_plain_hex.length - 64), 16)
        let signature = {r: r, s: s}

        let plainBytes = cryptoJS.enc.Hex.parse(sig_plain_hex.substring(0, sig_plain_hex.length - 128))

        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(plainBytes)
        const dig = sha256.finalize()
        let hash = new BN(cryptoJS.enc.Hex.stringify(dig), 16)

        // Verify signature
        // let ecdsa = new elliptic.ec(P256)
        if (!P256.verify(hash, signature, remoteAuthPub)) {
            return [false, undefined]
        }

        return [true, plainBytes]
    }

    /**
     * Encrypt a string to a cypher string.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param plain
     * @return {Promise<string>} cypher data is a string encoded in base64.
     */
    export async function encryptString(localAuthPriv: BN, remoteAuthPub: any, plain: string) : Promise<string>{
        return _encrypt(localAuthPriv, remoteAuthPub, plain)
    }

    /**
     * Decrypt cypher data to a string.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param cypher
     * @return {[boolean, string]} [ok, plain]
     */
    export function decryptString(localAuthPriv: BN, remoteAuthPub: any, cypher: string): [boolean, string] {
        let [ok, cjsBytes] = _decrypt(localAuthPriv, remoteAuthPub, cypher)
        if(ok){
            return [true, cryptoJS.enc.Utf8.stringify(cjsBytes)]
        }else {
            return [false, null]
        }
    }

    /**
     * Encrypt the CryptoJSBytes to a cypher string.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param plain
     * @return {Promise<string>} cypher
     */
    export async function encryptCryptoJSBytes(localAuthPriv: BN, remoteAuthPub: any, plain: CryptoJSBytes) : Promise<string>{
        return _encrypt(localAuthPriv, remoteAuthPub, plain)
    }

    /**
     * Decrypt a cypher string to plain CryptoJSBytes.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param cypher
     * @return {[boolean, CryptoJSBytes]} [ok, plain]
     */
    export function decryptCryptoJSBytes(localAuthPriv: BN, remoteAuthPub: any, cypher: string): [boolean, CryptoJSBytes] {
        return _decrypt(localAuthPriv, remoteAuthPub, cypher)
    }

    /**
     * Encrypt the Bytes to a cypher string.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param plain
     * @return {Promise<string>} cypher
     */
    export async function encryptBytes(localAuthPriv: BN, remoteAuthPub: any, plain: number[]) : Promise<string>{
        return await _encrypt(localAuthPriv, remoteAuthPub, plain)
    }

    /**
     * Decrypt a cypher string to plain bytes.
     * @param localAuthPriv
     * @param remoteAuthPub
     * @param cypher
     * @return {[boolean, number[]]} [ok, plain]
     */
    export function decryptBytes(localAuthPriv: BN, remoteAuthPub: any, cypher: string): [boolean, number[]] {
        let [ok, cjsBytes] = _decrypt(localAuthPriv, remoteAuthPub, cypher)
        if (ok) {
            return [true, Hex.toBytes(Hex.fromCryptoJSBytes(cjsBytes))]
        } else {
            return [false, null]
        }
    }
}