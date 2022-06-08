'use strict'

const assert = require('assert')
const BN = require('../node_modules/bn.js/lib/bn');

const Rand = require('@safeheron/crypto-rand')
const EC = require('elliptic').ec;
const P256 = new EC('p256')
const ECEnc = require('../lib/ecies')

const CryptoJS = require("crypto-js")
const utils = require("../lib/common/utils")

describe('Elliptic Curve Encryption', function () {
    it('Encrypt Bytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a"
            let data = CryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECEnc.encryptBytes(pub, data)
            console.log('cypher: ', CryptoJS.enc.Hex.stringify(cypher))
            let plain = ECEnc.decryptBytes(priv, cypher)
            console.log(CryptoJS.enc.Hex.stringify(plain))
        }
    });

    it('Encrypt long Bytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a"
            let data = CryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECEnc.encryptBytes(pub, data)
            console.log("cypher: ", CryptoJS.enc.Hex.stringify(cypher))
            let plain = ECEnc.decryptBytes(priv, cypher)
            console.log("plain: ", CryptoJS.enc.Hex.stringify(plain))
        }
    });
    it('Encrypt utf8 encode ', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            // default utf8 decode
            let msgUtf = 'hello world'
            let cypher = await ECEnc.encryptBytes(pub, msgUtf)
            console.log("cypher: ", CryptoJS.enc.Hex.stringify(cypher))
            let plain = ECEnc.decryptBytes(priv, cypher)
            console.log("plain: ", CryptoJS.enc.Utf8.stringify(plain))
        }
    });

    it('EncryptwithRIV', async function () {
        let priv = new BN('542EE1CCB70AE3FEB94607D695ACDB3CA6630B7827113147FD0B509A86AEB2DB', 16)
        let pub = P256.g.mul(priv)
        //console.log(pub.getX().toString(16))
        let msg = [0, 1, 2, 3, 4, 5]
        let msgUtf = CryptoJS.enc.Hex.parse(utils.toHex(msg))
        //let msgHex = "f176f4abeab66ecaab6366a7bb17860690e1c94658a04a5fd1893f1fb6783e01"
        //let data = CryptoJS.enc.Hex.parse(utils.padToByte32(msgHex))
        let r = new BN("D76D0F6A427C860337262BA519A861ABF7C59BC419177525F83394C21DA55AE7", 16)
        let iv = new BN("0B70C4E730C20761E397AB9EE83D7B04", 16)
        let cypher = await ECEnc.encryptBytesWithRIV(pub, msgUtf, r, iv)
        //let cypher = await ECEnc.encryptBytes(pub, msgUtf)
        console.log("cypher: ", CryptoJS.enc.Hex.stringify(cypher).substring(224))
        let plain = ECEnc.decryptBytes(priv, cypher)
        console.log("plain: ", CryptoJS.enc.Hex.stringify(plain))
    });


    it('Encrypt long Bytes', async function () {
        let priv = new BN('9217804d34b7c5da782df9870b2e0ce030782a5958fefb2d9e0caafef26faa73', 16)
        let pub = P256.g.mul(priv)
        //console.log(pub.getX().toString(16))
        let msgHex = "f176f4abeab66ecaab6366a7bb17860690e1c94658a04a5fd1893f1fb6783e01"
        let data = CryptoJS.enc.Hex.parse(utils.padToByte32(msgHex))
        let cypher = await ECEnc.encryptBytes(pub, data)
        console.log("cypher: ", CryptoJS.enc.Hex.stringify(cypher))
        let plain = ECEnc.decryptBytes(priv, cypher)
        console.log("plain: ", CryptoJS.enc.Hex.stringify(plain))
    });

    it('Encrypt long Bytes new', async function () {
        let priv = new BN('f3b2fe9bd8329829ce58d0b5e9923b5b644ece93391db6268b2b6f9ea72326f6', 16)
        //console.log(utils.padToByte32(priv.toString(16)))
        let pub = P256.g.mul(priv)
        //console.log(pub.getX().toString(16))
        let msgHex = "4528e2cb388bec979764e2656ba502926871dfc67cbd87c565e14e730a5349b2"
        let data = CryptoJS.enc.Hex.parse(utils.padToByte32(msgHex))
        let cypher = await ECEnc.encryptBytes(pub, data)
        console.log('cypher: ', CryptoJS.enc.Hex.stringify(cypher))

        let plain = ECEnc.decryptBytes(priv, cypher)
        console.log("plain: ", CryptoJS.enc.Hex.stringify(plain))
    });
})