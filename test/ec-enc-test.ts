import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import {Rand, Prime} from "@safeheron/crypto-rand"
const P256 = elliptic.ec('p256')
import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"
import {ECIES, AuthEnc} from ".."
import * as assert from "assert";

describe('ECIES_CryptoJSBytes', function () {
    it('Encrypt CryptoJSBytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a"
            let data = cryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
            console.log('cypher: ', cryptoJS.enc.Hex.stringify(cypher))
            let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
            let plainHex = cryptoJS.enc.Hex.stringify(plain)
            console.log("plainHex: ", plainHex)
            assert.equal(msgHex, plainHex)
        }
    });

    it('Encrypt long CryptoJSBytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a"
            let data = cryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
            console.log("cypher: ", cryptoJS.enc.Hex.stringify(cypher))
            let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
            let plainHex = cryptoJS.enc.Hex.stringify(plain)
            console.log("plainHex: ", plainHex)
            assert.equal(msgHex, plainHex)
        }
    });

    it('EncryptwithRIV', async function () {
        let priv = new BN('542EE1CCB70AE3FEB94607D695ACDB3CA6630B7827113147FD0B509A86AEB2DB', 16)
        let pub = P256.g.mul(priv)
        let msgHex = "123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a"
        let data = cryptoJS.enc.Hex.parse(msgHex)
        let r = new BN("D76D0F6A427C860337262BA519A861ABF7C59BC419177525F83394C21DA55AE7", 16)
        let iv = Hex.toCryptoJSBytes("0B70C4E730C20761E397AB9EE83D7B04")
        let cypher = await ECIES.encryptCryptoJSBytesWithRIV(pub, data, r, iv)
        console.log("cypher: ", cryptoJS.enc.Hex.stringify(cypher).substring(224))
        let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
        let plainHex = cryptoJS.enc.Hex.stringify(plain)
        console.log("plainHex: ", plainHex)
        assert.equal(msgHex, plainHex)
    });


    it('Encrypt long CryptoJSBytes', async function () {
        let priv = new BN('9217804d34b7c5da782df9870b2e0ce030782a5958fefb2d9e0caafef26faa73', 16)
        let pub = P256.g.mul(priv)
        let msgHex = "f176f4abeab66ecaab6366a7bb17860690e1c94658a04a5fd1893f1fb6783e01"
        let data = Hex.toCryptoJSBytes(Hex.pad64(msgHex))
        let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
        console.log("cypher: ", cryptoJS.enc.Hex.stringify(cypher))
        let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
        let plainHex = cryptoJS.enc.Hex.stringify(plain)
        console.log("plainHex: ", plainHex)
        assert.equal(msgHex, plainHex)
    });

    it('Encrypt long Bytes new', async function () {
        let priv = new BN('f3b2fe9bd8329829ce58d0b5e9923b5b644ece93391db6268b2b6f9ea72326f6', 16)
        let pub = P256.g.mul(priv)
        let msgHex = "4528e2cb388bec979764e2656ba502926871dfc67cbd87c565e14e730a5349b2"
        let data = Hex.toCryptoJSBytes(Hex.pad64(msgHex))
        let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
        console.log('cypher: ', cryptoJS.enc.Hex.stringify(cypher))

        let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
        let plainHex = cryptoJS.enc.Hex.stringify(plain)
        console.log("plainHex: ", plainHex)
        assert.equal(msgHex, plainHex)
    });
})

describe('ECIES_string', function () {
    it('Encrypt a string', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msg = 'hello world'
            let cypher = await ECIES.encryptString(pub, msg)
            console.log("cypher: ", Hex.fromBytes(cypher))
            let plain = ECIES.decryptString(priv, cypher)
            console.log("plain: ", plain)
            assert.equal(msg, plain)
        }
    });
})

describe('ECIES_Bytes', function () {
    it('Encrypt Bytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
            let cypher = await ECIES.encryptBytes(pub, data)
            console.log('cypher: ', Hex.fromBytes(cypher))
            let plain = ECIES.decryptBytes(priv, cypher)
            console.log("plain data: ", Hex.fromBytes(plain))
            assert.equal(data.length, plain.length)
            for(let i = 0; i < data.length; i++){
                assert.equal(data.at(i), plain.at(i))
            }
        }
    });

})
