'use strict';
var forge = require('node-forge');
const crypto = require('crypto');
const EventEmitter = require('events');
const util = require('util');

function IntegrityKey() {
    EventEmitter.call(this);
    var integritykey = integritykey;

    this.setintegritykey = function(s) {
        integritykey = s;
    }

    this.getintegritykey = function() {
        return integritykey;
    }
}
util.inherits(IntegrityKey, EventEmitter);
IntegrityKey.prototype.__proto__ = EventEmitter.prototype;

IntegrityKey.prototype.GenerateIntegrityKey = function(SessionResult) {
   // var bytesv2 = []; // char codes
    var bytes = [];

    for (var i = 0; i < SessionResult.length; ++i) {
        var code = SessionResult.charCodeAt(i);
        bytes = bytes.concat([code]);
      //  bytesv2 = bytesv2.concat([code & 0xff, code / 256 >>> 0]);
    }
   // console.log("lenght is" + bytes.length)
    var IntegrityArray = bytes.slice(Math.min(bytes.length/2,16),Math.min(bytes.length,32));
    //console.log("hash " + IntegrityArray.bytes);

    this.setintegritykey(IntegrityArray);
}
IntegrityKey.prototype.returnIntegrityKey = function(SessionResult) {
    return this.getintegritykey();
}


module.exports = IntegrityKey