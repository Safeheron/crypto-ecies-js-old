'use strict';

var utils = exports;
var BN = require('bn.js')

function toArray(msg, enc) {
  if (Array.isArray(msg))
    return msg.slice();
  if (!msg)
    return [];
  var res = [];
  if (typeof msg !== 'string') {
    for (var i = 0; i < msg.length; i++)
      res[i] = msg[i] | 0;
    return res;
  }
  if (enc === 'hex') {
    msg = msg.replace(/[^a-z0-9]+/ig, '');
    if (msg.length % 2 !== 0)
      msg = '0' + msg;
    for (var i = 0; i < msg.length; i += 2)
      res.push(parseInt(msg[i] + msg[i + 1], 16));
  } else {
    for (var i = 0; i < msg.length; i++) {
      var c = msg.charCodeAt(i);
      var hi = c >> 8;
      var lo = c & 0xff;
      if (hi)
        res.push(hi, lo);
      else
        res.push(lo);
    }
  }
  return res;
}
utils.toArray = toArray;

function zero2(word) {
  if (word.length === 1)
    return '0' + word;
  else
    return word;
}
utils.zero2 = zero2;

function toHex(msg) {
  var res = '';
  for (var i = 0; i < msg.length; i++)
    res += zero2(msg[i].toString(16));
  return res;
}
utils.toHex = toHex;

function toReverseHex(msg) {
  var res = '';
  for (var i = msg.length - 1; i >= 0; i--)
    res += zero2(msg[i].toString(16));
  return res;
}
utils.toReverseHex = toReverseHex;

utils.encode = function encode(arr, enc) {
  if (enc === 'hex')
    return toHex(arr);
  else
    return arr;
};

function toUnit8Array(buf){
  let arr = new Uint8Array(buf.length)
  for(let i = 0; i < buf.length; i ++){
    arr[i] = buf[i]
  }
  return arr
}
utils.toUnit8Array = toUnit8Array

/**
 * Pad the bytes to the specified length 'byteLen'
 * @param byteStr. String which mean the bytes. For example "01020304"
 * @param byteLen. For example 8
 * @returns {*} For example "0000000001020304"
 */
function padToLength (byteStr, byteLen) {
  while(byteLen * 2 > byteStr.length) {
    byteStr = '0' + byteStr
  }
  return byteStr
}
utils.padToLength = padToLength

/**
 * Pad the bytes to 32 bytes
 * @param byteStr
 * @returns {*}
 */
function padToByte32 (byteStr) {
  return padToLength(byteStr, 32)
}
utils.padToByte32 = padToByte32

/**
 * Pad the bytes to 16 bytes
 * @param byteStr
 * @returns {*}
 */
function padToByte16 (byteStr) {
  return padToLength(byteStr, 16)
}
utils.padToByte16 = padToByte16

/**
 * Pad the bytes to 4 bytes
 * @param byteStr
 * @returns {*}
 */
function padToByte4 (byteStr) {
  return padToLength(byteStr, 4)
}
utils.padToByte4 = padToByte4

/**
 * Pad the bytes to 1 bytes
 * @param byteStr
 * @returns {*}
 */
function padToByte1 (byteStr) {
  return padToLength(byteStr, 1)
}

utils.padToByte1 = padToByte1

/**
 * Pad the bytes to even bytes
 * @param byteStr
 * @returns {*}
 */
function padToByteEven (byteStr) {
  if(byteStr.length % 2 !== 0){
    byteStr = padToLength(byteStr, byteStr.length + 1)
  }
  return byteStr
}

utils.padToByteEven = padToByteEven

function BN2String (bn) {
  return bn.toString(16)
}
utils.BN2String = BN2String

function String2BN(bnHexStr) {
  return new BN(bnHexStr, 16)
}
utils.String2BN = String2BN

function BN2ByteStr (bn, byteLength) {
  return padToLength(bn.toString(16), byteLength)
}
utils.BN2ByteStr = BN2ByteStr


