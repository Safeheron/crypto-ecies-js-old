const CryptoJS = require("crypto-js")
const CryptoJSPatch= exports

CryptoJSPatch.hex2wordArray= function (hexStr) {
    if(hexStr.length % 2 === 1){
        hexStr = '0' + hexStr
    }
    return CryptoJS.enc.Hex.parse(hexStr)
}

