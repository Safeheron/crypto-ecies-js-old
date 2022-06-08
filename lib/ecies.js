//import {toHex} from "./common/utils"
const CryptoJS = require("crypto-js")
const EC = require('elliptic').ec;
const rand = require('@safeheron/crypto-rand')
const utils = require("./common/utils")
const P256 = new EC('p256')

const ECEnc = exports

/**
 * Encryption.
 * @param pub. ECC Public Key
 * @param plainBytes
 * @returns {Promise<(*|BN|string|T[]|T[]|Buffer|WordArray)[]>}
 * @private
 */
async function _encrypt(pub, plainBytes){
    const r = await rand.randomBNLt(P256.n)
    const iv = await rand.randomBN(16)
    return _encryptWithRIV(pub, plainBytes, r, iv)
}



/**
 * Encryption.
 * @param pub. ECC Public Key
 * @param plainBytes
 * @returns {Promise<(*|BN|string|T[]|T[]|Buffer|WordArray)[]>}
 * @private
 */
function _encryptWithRIV(pub, plainBytes, r, iv){
    // Get Key
    let gR = P256.g.mul(r)
    let keyPoint = pub.mul(r)

    //generate seed
    let keyPoint_x = keyPoint.getX()
    let seed_WordArray = CryptoJS.lib.WordArray.create();

    seed_WordArray.concat(CryptoJS.enc.Hex.parse(utils.padToLength(utils.toHex(gR.encode()),65)))
    seed_WordArray.concat(CryptoJS.enc.Hex.parse(utils.padToByte32(keyPoint_x.toString(16))))

    let symm_key_size = 256 / 8
    let mac_key_size = 512 / 8
    let digestLength = 256 / 8

    let derivation_key = ''
    let totalLength = symm_key_size + mac_key_size
    for(let i = 1; i <= totalLength / digestLength; i++) {
        let sha256 = CryptoJS.algo.SHA256.create();
        let i_WordArray = CryptoJS.enc.Hex.parse(utils.padToLength(i.toString(16), 4))
        sha256.update(seed_WordArray)
        sha256.update(i_WordArray)
        let digest = sha256.finalize();
        derivation_key += utils.padToByte32(digest.toString(CryptoJS.enc.Hex))
    }

    let symm_key = derivation_key.substring(0, symm_key_size * 2)
    let mac_key = derivation_key.substring(symm_key_size * 2, derivation_key.length)

    let iv_bytes = CryptoJS.enc.Hex.parse(utils.padToByte16(iv.toString(16)))

    // AES256, CBC default
    let aesEncryptor = CryptoJS.algo.AES.createEncryptor(CryptoJS.enc.Hex.parse(symm_key), {iv:iv_bytes})
    let cypher1 = aesEncryptor.process(plainBytes)
    let cypher2 = aesEncryptor.finalize()
    let cypher = cypher1.concat(cypher2)

    let hmac_sha256 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, CryptoJS.enc.Hex.parse(mac_key));
    hmac_sha256.update(cypher);
    let mac_cypher = hmac_sha256.finalize();

    return [gR.getX(), gR.getY(), iv_bytes, mac_cypher, cypher]
}

/**
 * Decryption
 * @param gR. Curve.g^R
 * @param priv.
 * @param iv. 16 bytes.
 * @param cypherPart
 * @returns {string | T[] | T[] | Buffer | WordArray}
 * @private
 */
function _decrypt(gR, priv, iv_bytes, macCypher, cypherPart) {
    // Get key
    let keyPoint = gR.mul(priv)

    //generate seed
    let keyPoint_x = keyPoint.getX()
    let seed_WordArray = CryptoJS.lib.WordArray.create();
    seed_WordArray.concat(CryptoJS.enc.Hex.parse(utils.padToLength(utils.toHex(gR.encode()),65)))
    seed_WordArray.concat(CryptoJS.enc.Hex.parse(utils.padToByte32(keyPoint_x.toString(16))))

    let symm_key_size = 256 / 8
    let mac_key_size = 512 / 8
    let digestLength = 256 / 8

    let derivation_key = ''
    let totalLength = symm_key_size + mac_key_size
    for(let i = 1; i <= totalLength / digestLength; i++) {
        let sha256 = CryptoJS.algo.SHA256.create();
        let i_WordArray = CryptoJS.enc.Hex.parse(utils.padToLength(i.toString(16), 4))
        sha256.update(seed_WordArray)
        sha256.update(i_WordArray)
        let digest = sha256.finalize();
        derivation_key += utils.padToByte32(digest.toString(CryptoJS.enc.Hex))
    }

    let symm_key = derivation_key.substring(0, symm_key_size * 2)
    let mac_key = derivation_key.substring(symm_key_size * 2, derivation_key.length)

    //cal mac for cypher
    let hmac_sha256 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, CryptoJS.enc.Hex.parse(mac_key));
    hmac_sha256.update(cypherPart);
    let mac_cypher = hmac_sha256.finalize();

    if(mac_cypher.toString(CryptoJS.enc.Hex) != macCypher.toString(CryptoJS.enc.Hex)) {
        console.log('mac_cypher != macCypher')
        return [false, 'mac verify error!']
    }

    // Decrypt
    let aesDecryptor = CryptoJS.algo.AES.createDecryptor(CryptoJS.enc.Hex.parse(symm_key), { iv: iv_bytes });
    let plainPart1 = aesDecryptor.process(cypherPart);
    let plainPart2 = aesDecryptor.finalize();
    return plainPart1.concat(plainPart2)
}

/**
 *
 * @param pub. ECC Public Key
 * @param plainBytes.
 * @returns {Promise<string>}
 */
ECEnc.encryptBytes = async function(pub, plainBytes){
    let [x_gR, y_gR, iv_bytes, macCypher, cypherPart] = await _encrypt(pub, plainBytes)
    let xBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(x_gR.toString(16)))
    let yBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(y_gR.toString(16)))
    return xBytes.concat(yBytes).concat(iv_bytes).concat(macCypher).concat(cypherPart)
}

/**
 *
 * @param pub. ECC Public Key
 * @param plainBytes.
 * @param r. BN
 * @param iv. BN
 * @returns {Promise<string>}
 */
ECEnc.encryptBytesWithRIV = async function(pub, plainBytes, r, iv){
    let [x_gR, y_gR, iv_bytes, macCypher, cypherPart] = await _encryptWithRIV(pub, plainBytes, r, iv)
    let xBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(x_gR.toString(16)))
    let yBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(y_gR.toString(16)))
    return xBytes.concat(yBytes).concat(iv_bytes).concat(macCypher).concat(cypherPart)
}

/**
 * Decrypt bytes.
 * @param priv. Private Key.
 * @param cypherBytes
 * @returns {string|T[]|Buffer|WordArray}
 */
ECEnc.decryptBytes = function(priv, cypherBytes){
    // Split cypher data
    let cypherStr = CryptoJS.enc.Hex.stringify(cypherBytes)
    let start = 0
    let gR_x = cypherStr.substring(start, start + 64)
    start += 64
    let gR_y = cypherStr.substring(start, start + 64)
    start += 64
    let iv =  cypherStr.substring(start, start + 32)
    start += 32
    let macCypher = cypherStr.substring(start, start + 64)
    start += 64
    let cypherPart = cypherStr.substring(start)
    // Get Key and IV
    let gR = P256.curve.point(gR_x, gR_y)
    let iv_bytes = CryptoJS.enc.Hex.parse(iv)
    macCypher = CryptoJS.enc.Hex.parse(macCypher)
    cypherPart = CryptoJS.enc.Hex.parse(cypherPart)
    return _decrypt(gR, priv, iv_bytes, macCypher, cypherPart)
}

