'use strict'

const assert = require('assert')
const BN = require('bn.js');

const Rand = require('@safeheron/crypto-rand')
const EC = require('elliptic').ec;
const P256 = new EC('p256')
const ECEnc = require('../lib/ecies')

const CryptoJS = require("crypto-js")
const CryptoJSPatch = require("../lib/common/cryptoJsPatch")
const utils = require("../lib/common/utils")

describe('Elliptic Curve Encryption', function () {
    it('Encrypt Bytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv:', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a"
            let data = CryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECEnc.encryptBytes(pub, msgHex)
            console.log(CryptoJS.enc.Hex.stringify(cypher))
            let plain = ECEnc.decryptBytes(priv, cypher)
            console.log(CryptoJS.enc.Hex.stringify(plain))
        }
    });

    it('Encrypt long Bytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv:', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a"
            let data = CryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECEnc.encryptBytes(pub, data)
            console.log("cypher:", CryptoJS.enc.Hex.stringify(cypher))
            let plain = ECEnc.decryptBytes(priv, cypher)
            console.log("plain:", CryptoJS.enc.Hex.stringify(plain))
        }
    });

    it('Encrypt long Bytes', async function () {
        let priv = new BN('9217804d34b7c5da782df9870b2e0ce030782a5958fefb2d9e0caafef26faa73', 16)
        let pub = P256.g.mul(priv)
        console.log(pub.getX().toString(16))
        let msgHex = "f176f4abeab66ecaab6366a7bb17860690e1c94658a04a5fd1893f1fb6783e01"
        let data = CryptoJS.enc.Hex.parse(utils.padToByte32(msgHex))
        let cypher = await ECEnc.encryptBytes(pub, data)
        console.log("cypher:", CryptoJS.enc.Hex.stringify(cypher))
        let plain = ECEnc.decryptBytes(priv, cypher)
        console.log("plain:", CryptoJS.enc.Hex.stringify(plain))
    });

    it('Encrypt long Bytes new', async function () {
        let priv = new BN('f3b2fe9bd8329829ce58d0b5e9923b5b644ece93391db6268b2b6f9ea72326f6', 16)
        console.log(utils.padToByte32(priv.toString(16)))
        let pub = P256.g.mul(priv)
        console.log(pub.getX().toString(16))
        let msgHex = "4528e2cb388bec979764e2656ba502926871dfc67cbd87c565e14e730a5349b2"
        let data = CryptoJS.enc.Hex.parse(utils.padToByte32(msgHex))
        let cypher = await ECEnc.encryptBytes(pub, data)
        console.log(CryptoJS.enc.Hex.stringify(cypher))

        //let cypherHex = "96fb39fcb368b00048fe41d62bc80dacb5f57d820d10889a8555e5b294e099bb12058d05947a34a6c40e2ac9d2d86c6486874e1377cb702ea3f85d2bb64753994add2cc7288a417f888ebf7b43ec047bcc5ee24bbb632af77e9bab5d3e298247b38ee91319b8a74a335f91d2cefac9870b18abbc109842f1d0f255ee53a6ecd3"
        let cypherHex = CryptoJS.enc.Hex.stringify(cypher)
        let cypherData = CryptoJS.enc.Hex.parse(utils.padToByte32(cypherHex))
        // let plain = ECEnc.decryptBytes(priv, cypherData)
        let plain = ECEnc.decryptBytes(priv, cypher)
        console.log("plain:", CryptoJS.enc.Hex.stringify(plain))
    });
})