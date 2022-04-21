/**
 * Convert binary data to and from UrlBase64 encoding.
 * This is identical to Base64 encoding, except that the padding character is "." and the other
 * non-alphanumeric characters are "-" and "_" instead of "+" and "/".
 * The purpose of UrlBase64 encoding is to provide a compact encoding of binary data that is safe
 * for use as an URL parameter. Base64 encoding does not produce encoded values that are safe for
 * use in URLs, since "/" can be interpreted as a path delimiter; "+" is the encoded form of a space;
 * and "=" is used to separate a name from the corresponding value in an URL parameter.
 */

const UrlBase64 = exports

const CryptoJS = require('crypto-js')

UrlBase64.parse = function (urlBase64) {
    let base64 = urlBase64.replace(/\./g, '=').replace(/-/g, '+').replace(/_/g, '/')
    return CryptoJS.enc.Base64.parse(base64)
}

UrlBase64.stringify = function (bytes) {
    let base64 = CryptoJS.enc.Base64.stringify(bytes)
    let urlBase64 = base64.replace(/=/g,'.').replace(/\+/g, '-').replace(/\//g, '_')
    return urlBase64
}
