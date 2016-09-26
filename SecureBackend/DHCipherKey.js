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

CipherKey.prototype.returnChipherKey = function(SessionResult) {
    return this.getcipherkey();
}
CipherKey.prototype.GenerateChipherKey = function(SessionResult) {
  // var bytesv2 = []; // char codes
    var bytes = [];

    for (var i = 0; i < SessionResult.length; ++i) {
        var code = SessionResult.charCodeAt(i);
        bytes = bytes.concat([code]);
      //  bytesv2 = bytesv2.concat([code & 0xff, code / 256 >>> 0]);
    }
   // console.log("lenght is" + bytes.length)
    var IntegrityArray = bytes.slice(0, Math.min(bytes.length/2,16));
    console.log("hash " + IntegrityArray.bytes);

    this.setcipherkey(IntegrityArray);
};


module.exports = CipherKey