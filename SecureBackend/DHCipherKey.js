'use strict';
var forge = require('node-forge');
const crypto = require('crypto');
const EventEmitter = require('events');
const util = require('util');

function CipherKey() {
    EventEmitter.call(this);
    // private
    var cipherkey = cipherkey;

    // public methods have access to private members
    this.setcipherkey = function(s) {
        cipherkey = s;
    }

    this.getcipherkey = function() {
        return cipherkey;
    }
}
util.inherits(CipherKey, EventEmitter);
CipherKey.prototype.__proto__ = EventEmitter.prototype;

CipherKey.prototype.GenerateChipherKeys = function(SessionResult) {
    const hash = crypto.createHash('sha256');
    var bytes = hash.update(SessionResult).digest('utf8');
    console.log(bytes.length)
    console.log(bytes.toString())
    var newArray = bytes.slice(0, 16);
    console.log(newArray.toString());
    this.setcipherkey(newArray);
}
CipherKey.prototype.returnChipherKey = function(SessionResult) {
    return this.getcipherkey();
}
CipherKey.prototype.GenerateChipherKey = function(SessionResult) {
    var key1 = crypto.createHash('sha256').update(SessionResult).digest('utf8');
    console.log(key1.length)
    console.log(key1.toString())
    var newArray = key1.slice(0, 16);
    var newArray1 = key1.slice(16, 32);
    console.log(newArray.length + newArray.toString())
    console.log("")
    console.log(newArray1.length + newArray1.toString())
    var iv = forge.random.getBytesSync(16);
    var cipher = forge.cipher.createCipher('AES-ECB', newArray1);
    cipher.start({
        iv: iv
    });
    cipher.update(forge.util.createBuffer("DDAS"));
    cipher.finish();
    var encrypted = cipher.output;
    // outputs encrypted hex
    console.log(encrypted.toHex());
    var decipher = forge.cipher.createDecipher('AES-ECB', newArray1);
    decipher.start({
        iv: null
    });
    decipher.update(encrypted);
    decipher.finish();
    // outputs decrypted hex
    console.log(decipher.output.data);
};


module.exports = CipherKey