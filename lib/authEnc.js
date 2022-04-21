const elliptic = require('elliptic')
const EC = require('elliptic').ec;
const BN = require('bn.js');
const assert = require('assert')
const rand = require('@safeheron/crypto-rand')

//const P256 = new EC('p256')
const CryptoJS = require("crypto-js")
const CryptoJSPatch = require("./common/cryptoJsPatch")
const EcEncrypt = require('./ecies')
const P256 = elliptic.curves['p256']
const utils = require('./common/utils')
const UrlBase64 = require('./common/urlBase64')

const AuthEnc = exports

/**
 * Authenticate and encrypt the data.
 * @param localAuthPriv
 * @param remoteAuthPub
 * @param plainBytes
 * @returns {Promise<(*|Signature)[]>}
 */
AuthEnc.encrypt = async function(localAuthPriv, remoteAuthPub, plain){
    let plainBytes = null
    if(typeof plain === 'string'){
        plainBytes = CryptoJS.enc.Utf8.parse(plain)
    }else if(plain instanceof Array){
        plainBytes = CryptoJS.enc.Hex.parse(utils.toHex(plain))
    }else{
        // CryptoJS.lib.WordArray
        plainBytes = plain
    }
    let cypherBytes = await EcEncrypt.encryptBytes(remoteAuthPub, plainBytes)

    // Get hash of cypher text
    const sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(cypherBytes)
    const dig = sha256.finalize()
    let hash = new BN(dig.toString(CryptoJS.enc.Hex), 16)

    // Get signature
    let ecdsa = new elliptic.ec(P256)
    let priv = ecdsa.keyFromPrivate(localAuthPriv)
    let signature = ecdsa.sign(hash, priv)

    let cypherWithSig = cypherBytes.concat(CryptoJS.enc.Hex.parse(utils.padToByte32(signature.r.toString(16))))
        .concat(CryptoJS.enc.Hex.parse(utils.padToByte32(signature.s.toString(16))))
    return UrlBase64.stringify(cypherWithSig)
}

/**
 * Verify the signatures and decrypt the data.
 * @param localAuthPriv
 * @param remoteAuthPub
 * @param cypher = cypherBytes + signature(64 byte)
 * @returns {[boolean, string]|[boolean, string]}
 */
AuthEnc.decrypt = function(localAuthPriv, remoteAuthPub, cypher){
    let cypherWithSigHex = CryptoJS.enc.Hex.stringify(UrlBase64.parse(cypher))
    assert(cypherWithSigHex.length > 128)
    let r = new BN(cypherWithSigHex.substr(cypherWithSigHex.length - 128, 64), 16)
    let s = new BN(cypherWithSigHex.substr(cypherWithSigHex.length - 64), 16)
    let cypherBytes = CryptoJS.enc.Hex.parse(cypherWithSigHex.substr(0, cypherWithSigHex.length - 128))
    let signature = {r: r, s: s}

    const sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(cypherBytes)
    const dig = sha256.finalize()
    let hash = new BN(CryptoJS.enc.Hex.stringify(dig), 16)

    // Verify signature
    let ecdsa = new elliptic.ec(P256)
    if(!ecdsa.verify(hash, signature, remoteAuthPub)){
        return [false, '']
    }

    // Decrypt
    let plainBytes = EcEncrypt.decryptBytes(localAuthPriv, cypherBytes)
    return [true, plainBytes]
}

AuthEnc.sign = async function(localAuthPriv, data){
    // Get hash of cypher text
    const sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(data)
    const dig = sha256.finalize()
    let hash = new BN(CryptoJS.enc.Hex.stringify(dig), 16)

    // Get signature
    let ecdsa = new elliptic.ec(P256)
    let priv = ecdsa.keyFromPrivate(localAuthPriv);
    let signature = ecdsa.sign(hash, priv);
    return utils.padToByte32(signature.r.toString(16))
        + utils.padToByte32(signature.s.toString(16))
}

/**
 * Verify the signatures and decrypt the data.
 * @param localAuthPriv
 * @param remoteAuthPub
 * @param cypherText
 * @param signature
 * @returns {[boolean, string]|[boolean, string]}
 */
AuthEnc.verify = function(authPub, data, signature){
    // Get r,s
    assert(signature.length === 128)
    const r = new BN(signature.substr(0, 64), 16)
    const s = new BN(signature.substr(64), 16)
    signature = { r: r, s: s }

    // Get hash of cypher text
    const sha256 = CryptoJS.algo.SHA256.create()
    sha256.update(data)
    const dig = sha256.finalize()
    let hash = new BN(dig.toString(CryptoJS.enc.Hex), 16)

    // Verify signature
    let ecdsa = new elliptic.ec(P256)
    return ecdsa.verify(hash, signature, authPub)
}
