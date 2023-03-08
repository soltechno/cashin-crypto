// @ts-nocheck
// Depends on jsbn.js and rng.js
// Version 1.1: support utf-8 encoding in pkcs1pad2
// convert a (hex) string to a bignum object
import { BigInteger, parseBigInt } from './jsbn';
import { SecureRandom } from './rng';

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s, n) {
    if (n < s.length + 11) { // TODO: fix for utf-8
        console.error('Message too long for RSA');
        return null;
    }
    var ba = [];
    var i = s.length - 1;
    while (i >= 0 && n > 0) {
        var c = s.charCodeAt(i--);
        if (c < 128) { // encode using utf-8
            ba[--n] = c;
        }
        else if ((c > 127) && (c < 2048)) {
            ba[--n] = (c & 63) | 128;
            ba[--n] = (c >> 6) | 192;
        }
        else {
            ba[--n] = (c & 63) | 128;
            ba[--n] = ((c >> 6) & 63) | 128;
            ba[--n] = (c >> 12) | 224;
        }
    }
    ba[--n] = 0;
    var rng = new SecureRandom();
    var x = [];
    while (n > 2) { // random non-zero pad
        x[0] = 0;
        while (x[0] == 0) {
            rng.nextBytes(x);
        }
        ba[--n] = x[0];
    }
    ba[--n] = 2;
    ba[--n] = 0;
    return new BigInteger(ba);
}
// "empty" RSA key constructor
var RSAKey = /** @class */ (function () {
    function RSAKey() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
    }
    //#region PROTECTED
    // protected
    // RSAKey.prototype.doPublic = RSADoPublic;
    // Perform raw public operation on "x": return x^e (mod n)
    RSAKey.prototype.doPublic = function (x) {
        return x.modPowInt(this.e, this.n);
    };

    // RSAKey.prototype.doPrivate = RSADoPrivate;
    // Perform raw private operation on "x": return x^d (mod n)
    RSAKey.prototype.doPrivate = function (x) {
        if (this.p == null || this.q == null) {
            return x.modPow(this.d, this.n);
        }
        // TODO: re-calculate any missing CRT params
        var xp = x.mod(this.p).modPow(this.dmp1, this.p);
        var xq = x.mod(this.q).modPow(this.dmq1, this.q);
        while (xp.compareTo(xq) < 0) {
            xp = xp.add(this.p);
        }
        return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
    };

    // RSAKey.prototype.encrypt = RSAEncrypt;
    // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
    RSAKey.prototype.encrypt = function (text) {
        var maxLength = (this.n.bitLength() + 7) >> 3;
        var m = pkcs1pad2(text, maxLength);
        if (m == null) {
            return null;
        }
        var c = this.doPublic(m);
        if (c == null) {
            return null;
        }
        var h = c.toString(16);
        var length = h.length;
        // fix zero before result
        for (var i = 0; i < maxLength * 2 - length; i++) {
            h = '0' + h;
        }
        return h;
    };

    // RSAKey.prototype.decrypt = RSADecrypt;
    // Return the PKCS#1 RSA decryption of "ctext".
    // "ctext" is an even-length hex string and the output is a plain string.
    RSAKey.prototype.decrypt = function (ctext) {
        var c = parseBigInt(ctext, 16);
        var m = this.doPrivate(c);
        if (m == null) {
            return null;
        }
        return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
    };

    return RSAKey;
}());
export { RSAKey };
// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d, n) {
    var b = d.toByteArray();
    var i = 0;
    while (i < b.length && b[i] == 0) {
        ++i;
    }
    if (b.length - i != n - 1 || b[i] != 2) {
        return null;
    }
    ++i;
    while (b[i] != 0) {
        if (++i >= b.length) {
            return null;
        }
    }
    var ret = '';
    while (++i < b.length) {
        var c = b[i] & 255;
        if (c < 128) { // utf-8 decode
            ret += String.fromCharCode(c);
        }
        else if ((c > 191) && (c < 224)) {
            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
            ++i;
        }
        else {
            ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
            i += 2;
        }
    }
    return ret;
}



