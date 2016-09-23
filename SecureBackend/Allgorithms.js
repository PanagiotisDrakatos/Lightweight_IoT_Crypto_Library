'use strict';
const EventEmitter = require('events');
const util = require('util');

function AlgorithmsUse() {
    EventEmitter.call(this);
    var CipherAlgorithm = CipherAlgorithm;
    var HashAlgorithm = HashAlgorithm;
    var CurrentHash = CurrentHash;

    this.setCurrentHash = function(s) {
        CurrentHash = s;
    }

    this.getCurrentHash = function() {
        return CurrentHash;
    }

    this.setHashAlgorithmy = function(s) {
        HashAlgorithm = s;
    }

    this.getHashAlgorithm = function() {
        return HashAlgorithm;
    }

    this.setCipherAlgorithm = function(s) {
        CipherAlgorithm = s;
    }

    this.getCipherAlgorithm = function() {
        return CipherAlgorithm;
    }
}
util.inherits(AlgorithmsUse, EventEmitter);
AlgorithmsUse.prototype.__proto__ = EventEmitter.prototype;

AlgorithmsUse.prototype.SetCurrentHash = function(Hash) {
    return this.setCurrentHash(Hash.toString());
}

AlgorithmsUse.prototype.returnCurrentHash = function() {
    return this.getCurrentHash().toString();
}

AlgorithmsUse.prototype.returnHashAlgorithm = function(SessionResult) {
    return this.getHashAlgorithm().toString();
}

AlgorithmsUse.prototype.returnCipherAlgorithm = function(SessionResult) {
    return this.getCipherAlgorithm().toString();
}
AlgorithmsUse.prototype.ChooserCipher = function(cipher) {
    this.setCipherAlgorithm(cipher[0]);
}

AlgorithmsUse.prototype.ChooserHash = function(Diggest) {
    this.setHashAlgorithmy(Diggest[2]);
}
module.exports = AlgorithmsUse