'use strict'

const assert = require('assert')
const BN = require('bn.js');

const Rand = require('@safeheron/crypto-rand')
const EC = require('elliptic').ec;
const P256 = new EC('p256')
const AuthEnc = require('../lib/authEnc')
const utils = require('../lib/common/utils')

const CryptoJS = require("crypto-js")
const CryptoJSPatch = require("../lib/common/cryptoJsPatch")

describe('Elliptic Curve Encryption', function () {
  it('Encrypt a string', async function () {
      let msg = 'hello'
      let localAuthPriv = await Rand.randomBN(32)
      let remoteAuthPriv = await Rand.randomBN(32)
      let localAuthPub = P256.g.mul(localAuthPriv)
      let remoteAuthPub = P256.g.mul(remoteAuthPriv)
      let cypherData = await AuthEnc.encrypt(localAuthPriv, remoteAuthPub, msg)
      console.log("cypherData:", cypherData)
      let [verifySig, plain] = AuthEnc.decrypt(remoteAuthPriv, localAuthPub, cypherData)
      if(verifySig){
          console.log("plainData:", CryptoJS.enc.Utf8.stringify(plain))
      }
      assert(verifySig)
  });

    it('Encrypt a Uint8Array', async function () {
        let msg = 'hello'
        msg = utils.toArray(msg)
        let localAuthPriv = await Rand.randomBN(32)
        let remoteAuthPriv = await Rand.randomBN(32)
        let localAuthPub = P256.g.mul(localAuthPriv)
        let remoteAuthPub = P256.g.mul(remoteAuthPriv)
        let cypherData = await AuthEnc.encrypt(localAuthPriv, remoteAuthPub, msg)
        console.log("cypherData:", cypherData)
        let [verifySig, plain] = AuthEnc.decrypt(remoteAuthPriv, localAuthPub, cypherData)
        if(verifySig){
            console.log("plainData:", CryptoJS.enc.Utf8.stringify(plain))
        }
        assert(verifySig)
    });

    it('Encrypt a WordArray', async function () {
        let msg = 'hello'
        msg = CryptoJS.enc.Utf8.parse(msg)
        let localAuthPriv = await Rand.randomBN(32)
        let remoteAuthPriv = await Rand.randomBN(32)
        let localAuthPub = P256.g.mul(localAuthPriv)
        let remoteAuthPub = P256.g.mul(remoteAuthPriv)
        let cypherData = await AuthEnc.encrypt(localAuthPriv, remoteAuthPub, msg)
        console.log("cypherData:", cypherData)
        let [verifySig, plain] = AuthEnc.decrypt(remoteAuthPriv, localAuthPub, cypherData)
        if(verifySig){
            console.log("plainData:", CryptoJS.enc.Utf8.stringify(plain))
        }
        assert(verifySig)
    });


    it('Elliptic Curve Author', async function () {
        let msg = 'hello'
        msg = CryptoJS.enc.Utf8.parse(msg)

        // local author key pair
        let authPriv = await Rand.randomBN(32)
        let authPub = P256.g.mul(authPriv)

        let signature = await AuthEnc.sign(authPriv, msg)
        console.log('sig:', signature)
        console.log('\n\n')
        let verifySig = AuthEnc.verify(authPub, msg, signature)
        assert(verifySig)
    });
})