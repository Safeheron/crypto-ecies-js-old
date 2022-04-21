const EC = require('elliptic').ec;
const BN = require('bn.js');
const assert = require('assert')
const rand = require('@safeheron/crypto-rand')

const P256 = new EC('p256')
const CryptoJS = require("crypto-js")
const CryptoJSPatch = require("./common/cryptoJsPatch")
const utils = require("./common/utils")

const ECEnc = exports

/**
 * Encryption.
 * @param pub. ECC Public Key
 * @param plainBytes
 * @returns {Promise<(*|BN|string|T[]|T[]|Buffer|WordArray)[]>}
 * @private
 */
async function _encrypt(pub, plainBytes){
    // Get Key
    const r = await rand.randomBNLt(P256.n)
    let gR = P256.g.mul(r)
    let keyPoint = pub.mul(r)
    let key = keyPoint.getX()
    key = CryptoJS.enc.Hex.parse(utils.padToByte32(key.toString(16)))
    // Get random IV: 16 bytes
    let iv = await rand.randomBN(16)
    iv = CryptoJS.enc.Hex.parse(utils.padToByte16(iv.toString(16)))
    // AES256, CBC default
    let aesEncryptor = CryptoJS.algo.AES.createEncryptor(key, {iv:iv})
    let cypher1 = aesEncryptor.process(plainBytes)
    let cypher2 = aesEncryptor.finalize()
    return [gR.getX(), gR.getY(), iv, cypher1.concat(cypher2)]
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
    let key = keyPoint.getX()
    key = CryptoJS.enc.Hex.parse(utils.padToByte32(key.toString(16)))

    // Encrypt
    let aesEncryptor = CryptoJS.algo.AES.createEncryptor(key, {iv:iv})
    let cypher1 = aesEncryptor.process(plainBytes)
    let cypher2 = aesEncryptor.finalize()

    return [gR.getX(), gR.getY(), cypher1.concat(cypher2)]
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
function _decrypt(gR, priv, iv, cypherPart){
    // Get key
    let keyPoint = gR.mul(priv)
    let key = keyPoint.getX()
    key = CryptoJS.enc.Hex.parse(utils.padToByte32(key.toString(16)))

    // Decrypt
    let aesDecryptor = CryptoJS.algo.AES.createDecryptor(key, { iv: iv });
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
    // Get Key
    const [x_gR, y_gR, iv, cypherPart] = await _encrypt(pub, plainBytes)
    let xBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(x_gR.toString(16)))
    let yBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(y_gR.toString(16)))
    return xBytes.concat(yBytes).concat(iv).concat(cypherPart)
}

/**
 *
 * @param pub. ECC Public Key
 * @param plainBytes.
 * @param r. BN
 * @param iv. WordArray
 * @returns {Promise<string>}
 */
ECEnc.encryptBytesWithRIV = async function(pub, plainBytes, r, iv){
    // Get Key
    const [x_gR, y_gR, cypherPart] = await _encryptWithRIV(pub, plainBytes, r, iv)
    let xBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(x_gR.toString(16)))
    let yBytes = CryptoJS.enc.Hex.parse(utils.padToByte32(y_gR.toString(16)))
    return xBytes.concat(yBytes).concat(iv).concat(cypherPart)
}

/**
 * Decrypt bytes.
 * @param priv. Private Key.
 * @param cypherBytes
 * @returns {string|T[]|Buffer|WordArray}
 */
ECEnc.decryptBytes = function(priv, cypherBytes){
    // Split cypher data
    let cypherText = CryptoJS.enc.Hex.stringify(cypherBytes)
    let pos = 0
    let pubX = cypherText.substr(pos, 64)
    pos += 64
    let pubY = cypherText.substr(pos, 64)
    pos += 64
    let iv = cypherText.substr(pos, 32)
    pos += 32
    let cypherPart = cypherText.substr(pos)

    // Get Key and IV
    let gR = P256.curve.point(pubX, pubY)
    iv = CryptoJS.enc.Hex.parse(iv)
    cypherPart = CryptoJS.enc.Hex.parse(cypherPart)
    return _decrypt(gR, priv, iv, cypherPart)
}
