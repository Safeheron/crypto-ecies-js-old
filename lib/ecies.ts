import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import {Rand, Prime} from "@safeheron/crypto-rand"
const P256 = elliptic.ec('p256')
import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"

export namespace ECIES {

    /**
     * Encryption.
     * @param pub. ECC Public Key
     * @param plainBytes
     * @returns {Promise<(*|BN|string|T[]|T[]|Buffer|WordArray)[]>}
     * @private
     */
    async function _encryptCryptoJSBytes(pub: any, plainBytes: CryptoJSBytes): Promise<[any, any, CryptoJSBytes, CryptoJSBytes, CryptoJSBytes]> {
        const r = await Rand.randomBNLt(P256.n)
        const ivBytes = await Rand.randomBytes(16)
        const ivCryptoJSBytes = Hex.toCryptoJSBytes(Hex.fromBytes(ivBytes))
        return _encryptCryptoJSBytesWithRIV(pub, plainBytes, r, ivCryptoJSBytes)
    }


    /**
     * Encryption.
     * @param pub. ECC Public Key
     * @param plainBytes
     * @param r
     * @param iv
     * @returns [any, any, CryptoJSBytes, CryptoJSBytes, CryptoJSBytes]: [gR.x, gR.y, iv, mac_cypher, cypher]
     * @private
     */
    function _encryptCryptoJSBytesWithRIV(pub: any, plainBytes: CryptoJSBytes, r: BN, iv: CryptoJSBytes): [any, any, CryptoJSBytes, CryptoJSBytes, CryptoJSBytes] {
        // Get Key
        let gR = P256.g.mul(r)
        let keyPoint = pub.mul(r)

        //generate seed
        let keyPoint_x = keyPoint.getX()
        let seed_WordArray = cryptoJS.lib.WordArray.create();

        seed_WordArray.concat(cryptoJS.enc.Hex.parse(Hex.padLength(Hex.fromBytes(gR.encode()), 65 * 2)))
        seed_WordArray.concat(cryptoJS.enc.Hex.parse(Hex.pad64(keyPoint_x.toString(16))))

        let symm_key_size = 256 / 8
        let mac_key_size = 512 / 8
        let digestLength = 256 / 8

        let derivation_key = ''
        let totalLength = symm_key_size + mac_key_size
        for (let i = 1; i <= totalLength / digestLength; i++) {
            let sha256 = cryptoJS.algo.SHA256.create();
            let i_WordArray = cryptoJS.enc.Hex.parse(Hex.pad8(i.toString(16)))
            sha256.update(seed_WordArray)
            sha256.update(i_WordArray)
            let digest = sha256.finalize();
            derivation_key += Hex.pad64(digest.toString(cryptoJS.enc.Hex))
        }

        let symm_key = derivation_key.substring(0, symm_key_size * 2)
        let mac_key = derivation_key.substring(symm_key_size * 2, derivation_key.length)

        let iv_bytes = iv

        // AES256, CBC default
        let aesEncryptor = cryptoJS.algo.AES.createEncryptor(cryptoJS.enc.Hex.parse(symm_key), {iv: iv_bytes})
        let cypher1 = aesEncryptor.process(plainBytes)
        let cypher2 = aesEncryptor.finalize()
        let cypher = cypher1.concat(cypher2)

        let hmac_sha256 = cryptoJS.algo.HMAC.create(cryptoJS.algo.SHA256, cryptoJS.enc.Hex.parse(mac_key));
        hmac_sha256.update(cypher);
        let mac_cypher = hmac_sha256.finalize();

        return [gR.getX(), gR.getY(), iv_bytes, mac_cypher, cypher]
    }

    /**
     * Decryption
     * @param gR. Curve.g^R
     * @param priv.
     * @param iv_bytes
     * @param macCypher
     * @param cypherPart
     * @returns CryptoJSBytes
     * @private
     */
    function _decryptCryptoJSBytes(gR: any, priv: BN, iv_bytes: CryptoJSBytes, macCypher: CryptoJSBytes, cypherPart: CryptoJSBytes): CryptoJSBytes {
        // Get key
        let keyPoint = gR.mul(priv)

        //generate seed
        let keyPoint_x = keyPoint.getX()
        let seed_WordArray = cryptoJS.lib.WordArray.create();
        seed_WordArray.concat(cryptoJS.enc.Hex.parse(Hex.padLength(Hex.fromBytes(gR.encode()), 65 * 2)))
        seed_WordArray.concat(cryptoJS.enc.Hex.parse(Hex.pad64(keyPoint_x.toString(16))))

        let symm_key_size = 256 / 8
        let mac_key_size = 512 / 8
        let digestLength = 256 / 8

        let derivation_key = ''
        let totalLength = symm_key_size + mac_key_size
        for (let i = 1; i <= totalLength / digestLength; i++) {
            let sha256 = cryptoJS.algo.SHA256.create();
            let i_WordArray = cryptoJS.enc.Hex.parse(Hex.pad8(i.toString(16)))
            sha256.update(seed_WordArray)
            sha256.update(i_WordArray)
            let digest = sha256.finalize();
            derivation_key += Hex.pad64(digest.toString(cryptoJS.enc.Hex))
        }

        let symm_key = derivation_key.substring(0, symm_key_size * 2)
        let mac_key = derivation_key.substring(symm_key_size * 2, derivation_key.length)

        //cal mac for cypher
        let hmac_sha256 = cryptoJS.algo.HMAC.create(cryptoJS.algo.SHA256, cryptoJS.enc.Hex.parse(mac_key));
        hmac_sha256.update(cypherPart);
        let mac_cypher = hmac_sha256.finalize();

        if (mac_cypher.toString(cryptoJS.enc.Hex) != macCypher.toString(cryptoJS.enc.Hex)) {
            throw 'Mac verify error: mac_cypher != macCypher'
        }

        // Decrypt
        let aesDecryptor = cryptoJS.algo.AES.createDecryptor(cryptoJS.enc.Hex.parse(symm_key), {iv: iv_bytes});
        let plainPart1 = aesDecryptor.process(cypherPart);
        let plainPart2 = aesDecryptor.finalize();
        return plainPart1.concat(plainPart2)
    }

    /**
     * Encrypt CryptoJSBytes to cypher CryptoJSBytes.
     * @param pub. ECC Public Key
     * @param plainBytes.
     * @returns {Promise<CryptoJSBytes>}
     */
    export async function encryptCryptoJSBytes(pub:any, plainBytes:  CryptoJSBytes): Promise<CryptoJSBytes>{
        let [x_gR, y_gR, iv_bytes, macCypher, cypherPart] = await _encryptCryptoJSBytes(pub, plainBytes)
        let xBytes = cryptoJS.enc.Hex.parse(Hex.pad64(x_gR.toString(16)))
        let yBytes = cryptoJS.enc.Hex.parse(Hex.pad64(y_gR.toString(16)))
        return xBytes.concat(yBytes).concat(iv_bytes).concat(macCypher).concat(cypherPart)
    }

    /**
     * Encrypt CryptoJSBytes to cypher CryptoJSBytes with specified random IV.
     * @param pub. ECC Public Key
     * @param plainBytes.
     * @param r. BN
     * @param iv. BN
     * @returns {Promise<CryptoJSBytes>}
     */
    export async function encryptCryptoJSBytesWithRIV(pub: any, plainBytes: CryptoJSBytes, r: BN, iv: CryptoJSBytes): Promise<CryptoJSBytes> {
        let [x_gR, y_gR, iv_bytes, macCypher, cypherPart] = await _encryptCryptoJSBytesWithRIV(pub, plainBytes, r, iv)
        let xBytes = cryptoJS.enc.Hex.parse(Hex.pad64(x_gR.toString(16)))
        let yBytes = cryptoJS.enc.Hex.parse(Hex.pad64(y_gR.toString(16)))
        return xBytes.concat(yBytes).concat(iv_bytes).concat(macCypher).concat(cypherPart)
    }

    /**
     * Decrypt CryptoJSBytes to plain CryptoBytes.
     * @param priv. Private Key.
     * @param cypherBytes
     * @returns {CryptoJSBytes}
     */
    export function decryptCryptoJSBytes(priv: BN, cypherBytes: CryptoJSBytes): CryptoJSBytes {
        // Split cypher data
        let cypherStr = cryptoJS.enc.Hex.stringify(cypherBytes)
        let start = 0
        let gR_x = cypherStr.substring(start, start + 64)
        start += 64
        let gR_y = cypherStr.substring(start, start + 64)
        start += 64
        let iv = cypherStr.substring(start, start + 32)
        start += 32
        let macCypher = cypherStr.substring(start, start + 64)
        start += 64
        let cypherPart = cypherStr.substring(start)
        // Get Key and IV
        let gR = P256.curve.point(gR_x, gR_y)
        let iv_bytes = cryptoJS.enc.Hex.parse(iv)
        macCypher = cryptoJS.enc.Hex.parse(macCypher)
        cypherPart = cryptoJS.enc.Hex.parse(cypherPart)
        return _decryptCryptoJSBytes(gR, priv, iv_bytes, macCypher, cypherPart)
    }

    /**
     * Encrypt bytes to cypher bytes.
     * @param pub. ECC Public Key
     * @param plainBytes.
     * @returns {Promise<number>} cypher bytes.
     */
    export async function encryptBytes(pub:any, plainBytes:  number[]): Promise<number[]>{
        plainBytes = Hex.toCryptoJSBytes(Hex.fromBytes(plainBytes))
        let cypherCryptoJSBytes = await encryptCryptoJSBytes(pub, plainBytes)
        return Hex.toBytes(Hex.fromCryptoJSBytes(cypherCryptoJSBytes))
    }

    /**
     * Decrypt cypher bytes to plain bytes.
     * @param priv. Private Key.
     * @param cypherBytes
     * @returns {number[]}
     */
    export function decryptBytes(priv: BN, cypherBytes: number[]): number[] {
        cypherBytes = Hex.toCryptoJSBytes(Hex.fromBytes(cypherBytes))
        let plainCryptoJSBytes = decryptCryptoJSBytes(priv, cypherBytes)
        return Hex.toBytes(Hex.fromCryptoJSBytes(plainCryptoJSBytes))
    }

    /**
     * Encrypt a string to cypher bytes.
     * @param pub. ECC Public Key
     * @param plainStr
     * @returns {Promise<number[]>}
     */
    export async function encryptString(pub:any, plainStr: string): Promise<number[]>{
        let cypherCryptoJSBytes = await encryptCryptoJSBytes(pub, plainStr)
        return Hex.toBytes(Hex.fromCryptoJSBytes(cypherCryptoJSBytes))
    }

    /**
     * Decrypt bytes to plain bytes.
     * @param priv. Private Key.
     * @param cypherBytes
     * @returns {string} plain
     */
    export function decryptString(priv: BN, cypherBytes: number[]): string {
        cypherBytes = Hex.toCryptoJSBytes(Hex.fromBytes(cypherBytes))
        let plainCryptoJSBytes = decryptCryptoJSBytes(priv, cypherBytes)
        return cryptoJS.enc.Utf8.stringify(plainCryptoJSBytes)
    }
}
