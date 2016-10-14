'use strict';

const EventEmitter = require('events');
const util = require('util');
var forge = require('node-forge');

var jsonToRead = require('./jsonObject.json');
var jsonToSend = require('./jsonObject.json');


var RandomGenerators = require('./RandomGenerator');
var RsaEncrypts = require("./RsaEncrypt");
var FingerPrint = require('./FingerPrint');
var ECB = require("./AES_ECB");
var CBC = require("./AES_CBC");
const HMAC = require('./HmacAlgProvider');
const AlgorithmsUse = require('./Allgorithms');

var Keypair = require('./RsaKeipairs');
var KeyHandle = require('./KeyManager')
var keystore = new KeyHandle();
var server = new Keypair(keystore);

var _Event = 'DHSessionHandshake';
var Generator = '';
var _ClientSymmetricKey;
var IntegrityKey = require('./DHintegrityKey')
var integritykey = new IntegrityKey();
var CipherKey = require('./DHCipherKey')
var cipherkey = new CipherKey();
var Algorithms = new AlgorithmsUse();

var count = 0;

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
    //clear();

    var serverprime = Generator.PublicPrimeNumber();
    jsonToSend.ServerPrimeNumber = serverprime;
    jsonToSend.PseudoNumber = Generator.pseudorandom();
    console.log(Generator.DHKeyExchange())
        //console.log("session keys is :" + Generator.DHKeyExchange());
    BasicProtocolEmmitter.prototype.on(_Event, ReceiveCipherSuites);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendPublicValue);
}

var ReceiveCipherSuites = function(ObjToRead) {

    jsonToRead = JSON.parse(ObjToRead);
    if (jsonToRead.PseudoNumber != Generator.pseudorandom())
        new Error('Can Not Valid Client Possible Replay Attack');

    integritykey.GenerateIntegrityKey(Generator.DHKeyExchange());
    var joiner = (jsonToRead.CipherSuites).split("|");
    var Chiphers = joiner[0].split(",");
    var Digests = joiner[1].split(",");
    var CurrentDiggests = joiner[2].split(",");

    if (CurrentDiggests.indexOf("Hmac_"))
        CurrentDiggests = CurrentDiggests.toString().replace(/Hmac_/i, '');
    else if (CurrentDiggests.indexOf("Hmac"))
        CurrentDiggests = CurrentDiggests.toString().replace(/Hmac/i, '');

    if (!HMAC.HmacVerify(jsonToRead.CipherSuites,
            integritykey.returnIntegrityKey(), jsonToRead.HmacHash, CurrentDiggests))
        new Error('Integrity Of Message can not be verified');
    Algorithms.ChooserCipher(Chiphers);
    Algorithms.ChooserHash(Digests);
    Algorithms.SetCurrentHash(CurrentDiggests);
    BasicProtocolEmmitter.prototype.on(_Event, SendCipherSuites);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceiveCipherSuites);
};

var SendCipherSuites = function() {
    clear();

    var Algo = '';
    Algo = Algo.concat(Algorithms.returnCipherAlgorithm(), '|');
    Algo = Algo.concat(Algorithms.returnHashAlgorithm(), '|');

    jsonToSend.CipherSuites = Algo;
    jsonToSend.PseudoNumber = Generator.pseudorandom();
    jsonToSend.HmacHash = HMAC.HmacSign(jsonToSend.CipherSuites, integritykey.returnIntegrityKey(), Algorithms.returnCurrentHash());

    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendCipherSuites);
};

var ReceiveDHEncryptedMessage = function(ObjToRead) {
    jsonToRead = JSON.parse(ObjToRead);
    console.log(jsonToRead.EncryptedMessage);
    if (!HMAC.HmacVerify(jsonToRead.EncryptedMessage, integritykey.returnIntegrityKey(),
            jsonToRead.HmacHash, Algorithms.returnHashAlgorithm()))
        new Error('Integrity Of Client Key canot be verified');

    cipherkey.GenerateChipherKey(Generator.DHKeyExchange());
    var _DecryptedMessage = CBC.AesDecryption(jsonToRead.EncryptedMessage, cipherkey.returnChipherKey());
    console.log('Clients says ' + _DecryptedMessage);
    BasicProtocolEmmitter.prototype.on(_Event, SendDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceiveDHEncryptedMessage);

};

var SendDHEncryptedMessage = function(ObjToRead) {
    clear();
    var _EncryptedMessage = CBC.AesEncryption(new Buffer("Helloclient" + count++), cipherkey.returnChipherKey());
    var _Mac = HMAC.HmacSign(_EncryptedMessage, integritykey.returnIntegrityKey(), Algorithms.returnCurrentHash());
    var _signature = FingerPrint.SignData(_EncryptedMessage, keystore.loadPrivateKey())

    jsonToSend.EncryptedMessage = _EncryptedMessage;
    jsonToSend.HmacHash = _Mac;
    jsonToSend.FingerPrint = _signature;

    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);
    BasicProtocolEmmitter.prototype.removeListener(_Event, SendDHEncryptedMessage);
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

module.exports = BasicProtocolEmmitter;