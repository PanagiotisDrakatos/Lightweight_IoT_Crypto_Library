'use strict';

const EventEmitter = require('events');
const util = require('util');


var jsonToRead = require('./jsonObject.json');
var jsonToSend = require('./jsonObject.json');


var forge = require('node-forge');
var fs = require('fs');
var RandomGenerators = require('./RandomGenerator');
var RsaEncrypts = require("./RsaEncrypt");
var FingerPrint = require('./FingerPrint');
var AesEncrypt = require("./AES_Encryption");

var Keypair = require('./RsaKeipairs');
var KeyHandle = require('./KeyManager')
var keystore = new KeyHandle();
var server = new Keypair(keystore);

var _Event = 'DHSessionHandshake';
var  Generator='';
var _ClientSymmetricKey;

module.exports = BasicProtocolEmmitter;

function BasicProtocolEmmitter() {
    EventEmitter.call(this);
    BasicProtocolEmmitter.IntializeCallbacks();
    Generator = new RandomGenerators();
    this.dataToSend = '';
}
util.inherits(BasicProtocolEmmitter, EventEmitter);

BasicProtocolEmmitter.prototype.__proto__ = EventEmitter.prototype;



BasicProtocolEmmitter.IntializeCallbacks = function() {
    BasicProtocolEmmitter.prototype.removeAllListeners();
    BasicProtocolEmmitter.prototype.on(_Event, ReceivePlainMessage);
}



BasicProtocolEmmitter.prototype.send = function() {
    // this.ReceivedData = data;
    BasicProtocolEmmitter.prototype.emit(_Event);
    return JSON.stringify(jsonToSend);
}
BasicProtocolEmmitter.prototype.Receive = function(ObjToRead) {
    // this.ReceivedData = data;
    BasicProtocolEmmitter.prototype.emit(_Event, ObjToRead);
    return JSON.stringify(jsonToSend);
}

var ReceivePlainMessage = function(ObjToRead) {
    jsonToRead = JSON.parse(ObjToRead);
    if (jsonToRead.PlainMessage != "ClientHello" ||
        jsonToRead.PseudoNumber != Generator.pseudorandom())
        new Error('Not Valid Protocol to Start');

    BasicProtocolEmmitter.prototype.on(_Event, SendCertificate);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceivePlainMessage);
};


var SendCertificate = function() {
    clear();
    jsonToSend.PlainMessage = "ServerHello";
    jsonToSend.PseudoNumber = Generator.pseudorandom();
    jsonToSend.CookieServer = Generator.CookieServer();
    jsonToSend.CertPemFormat = keystore.loadCertificate();
    BasicProtocolEmmitter.prototype.on(_Event, RepetitionPrevention);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendCertificate);
};

var RepetitionPrevention = function(ObjToRead) {
    jsonToRead = JSON.parse(ObjToRead);

    if (jsonToRead.PlainMessage != "Resend" ||
        jsonToRead.CookieServer != Generator.CookieServer() ||
        jsonToRead.PseudoNumber != Generator.pseudorandom())
        new Error('Can Not Valid Client Possible Replay Attack');

    BasicProtocolEmmitter.prototype.on(_Event, ReceivePublicValue);
    BasicProtocolEmmitter.prototype.removeListener(_Event, RepetitionPrevention);
};

var ReceivePublicValue = function(ObjToRead) {
    jsonToRead = JSON.parse(ObjToRead);

    if (jsonToRead.PseudoNumber != Generator.pseudorandom())
        new Error('Can Not Valid Client Possible Replay Attack');

    var ClientPublicNumber = RsaEncrypts.RsaDeCryption(keystore.loadPrivateKey(), jsonToRead.ClientEncryptedPrimeNumber);
    Generator.SessionGenerator(ClientPublicNumber);

    BasicProtocolEmmitter.prototype.on(_Event, SendPublicValue);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceivePublicValue);
};

var SendPublicValue = function() {
    clear();

    var serverprime = Generator.PublicPrimeNumber();
    jsonToSend.ServerPrimeNumber = serverprime;
    jsonToSend.PseudoNumber = Generator.pseudorandom();

    //console.log("session keys is :" + Generator.DHKeyExchange());
    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendPublicValue);
}

var ReceiveDHEncryptedMessage = function(ObjToRead) {


};

var SendDHEncryptedMessage = function(ObjToRead) {

};

function clear() {
    delete jsonToSend['PlainMessage'];
    delete jsonToSend['CookieServer'];
    delete jsonToSend['CertPemFormat'];
    delete jsonToSend['PseudoNumber'];
    delete jsonToSend['ClientEncryptedPrimeNumber'];
    delete jsonToSend['ServerPrimeNumber'];
    delete jsonToSend['EncryptedMessage'];
    delete jsonToSend['FingerPrint'];
    delete jsonToSend['HmacHash'];

}