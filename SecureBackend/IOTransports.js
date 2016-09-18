'use strict';

const EventEmitter = require('events');
const util = require('util');


var jsonToRead = require('./jsonObject.json');
var jsonToSend = require('./jsonObject.json');


var ursa = require('ursa');
var forge = require('node-forge');
var fs = require('fs');
var RandomGenerators = require('./RandomGenerator');
var RsaEncrypts = require("./RsaEncrypt");
var FingerPrint = require('./FingerPrint');
var AesEncrypt = require("./AES_Encryption");

var Keypair=require('./RsaKeipairs');
var KeyHandle=require('./KeyManager')
var keystore=new KeyHandle();
var server = new Keypair(keystore);

var _Event = 'DHSessionHandshake';

const Generator = new RandomGenerators();
var x = Generator.PrimeNumber();
var _ClientSymmetricKey;

module.exports = BasicProtocolEmmitter;

function BasicProtocolEmmitter() {
    EventEmitter.call(this);
    BasicProtocolEmmitter.IntializeCallbacks();
    this.dataToSend = '';
}
util.inherits(BasicProtocolEmmitter, EventEmitter);

BasicProtocolEmmitter.prototype.__proto__ = EventEmitter.prototype;



BasicProtocolEmmitter.IntializeCallbacks = function() {
    BasicProtocolEmmitter.prototype.removeAllListeners();
    BasicProtocolEmmitter.prototype.on(_Event, ReceiveClientrPublicKey);
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

var ReceiveClientrPublicKey = function(ObjToRead) {
    jsonToRead = JSON.parse(ObjToRead);
    // base64-decode DER bytes
    var certDerBytes = forge.util.decode64(jsonToRead.RSAPublicKey);
    var obj = forge.asn1.fromDer(certDerBytes);
    var publicKey = forge.pki.publicKeyFromAsn1(obj);
    var pem = forge.pki.publicKeyToPem(publicKey);
    Keypair.StoreClientPublic(pem);
    BasicProtocolEmmitter.prototype.on(_Event, SendServerPublicKey);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceiveClientrPublicKey);
};


var SendServerPublicKey = function() {
    jsonToSend.RSAPublicKey = _pubkeyServer.toPublicPem('utf8');
    BasicProtocolEmmitter.prototype.on(_Event, ReceivePrimeNumber);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendServerPublicKey);
};

var ReceivePrimeNumber = function(ObjToRead) {
    jsonToRead = JSON.parse(ObjToRead);

    if (!FingerPrint.verifySig(jsonToRead.EncryptedSymetricClientKey, forge.pki.publicKeyFromPem(_pubkeyClientpem), jsonToRead.fingerPrint)) {
        BasicProtocolEmmitter.prototype.removeAllListeners();
        new Error('Integrity Of Client Key canot be verified');
    }

    _ClientSymmetricKey = RsaEncrypts.RsaDeCryption(jsonToRead.EncryptedSymetricClientKey, _privkeyServer);

    var ClientPublicNumber = AesEncrypt.AesDecryption(jsonToRead.ClientEncryptedPrimeNumber, _ClientSymmetricKey, jsonToRead.HmacHash);

    Generator.SessionGenerator(ClientPublicNumber);

    BasicProtocolEmmitter.prototype.on(_Event, EndDHsession);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceivePrimeNumber);
};

var EndDHsession = function(ObjToRead) {
    delete jsonToSend['RSAPublicKey'];
    delete jsonToSend['EncryptedSymetricClientKey'];
    jsonToSend = require('./jsonObject.json');

    var _ServerPrimeNumberWithMac = AesEncrypt.AesEncryption(Generator.PublicPrimeNumber(), _ClientSymmetricKey);
    var _signature = FingerPrint.SignData(_ServerPrimeNumberWithMac.Encrypted, _privkeyServer);
    jsonToSend.ServerPrimeNumber = _ServerPrimeNumberWithMac.Encrypted;
    jsonToSend.HmacHash = _ServerPrimeNumberWithMac.Hmac;
    jsonToSend.fingerPrint = _signature;

    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, EndDHsession);
};


var ReceiveDHEncryptedMessage = function(ObjToRead) {

    jsonToRead = JSON.parse(ObjToRead);

    if (!FingerPrint.verifySig(jsonToRead.EncryptedMessage, forge.pki.publicKeyFromPem(_pubkeyClientpem), jsonToRead.fingerPrint)) {
        BasicProtocolEmmitter.prototype.removeAllListeners();
        new Error('Integrity Of Client Key canot be verified');
    }
    var _DecryptedMessage = AesEncrypt.AesDecryption(jsonToRead.EncryptedMessage, Generator.DHKeyExchange(), jsonToRead.HmacHash);
    console.log('Clients said+' + _DecryptedMessage);
    BasicProtocolEmmitter.prototype.on(_Event, SendDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceiveDHEncryptedMessage);
};

var SendDHEncryptedMessage = function(ObjToRead) {

    clear();
    var _EncryptedMessageWithMac = AesEncrypt.AesEncryption('HelloClient', Generator.DHKeyExchange());
    var _signature = FingerPrint.SignData(_EncryptedMessageWithMac.Encrypted, _privkeyServer);

    jsonToSend.EncryptedMessage = _EncryptedMessageWithMac.Encrypted;
    jsonToSend.HmacHash = _EncryptedMessageWithMac.Hmac;
    jsonToSend.fingerPrint = _signature;

    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendDHEncryptedMessage);
};

function clear() {
    delete jsonToSend['HmacHash'];
    delete jsonToSend['RSAPublicKey'];
    delete jsonToSend['ServerPrimeNumber'];
    delete jsonToSend['EncryptedMessage'];
    delete jsonToSend['EncryptedSymetricClientKey'];
    delete jsonToSend['ClientEncryptedPrimeNumber'];
    delete jsonToSend['fingerPrint'];
}