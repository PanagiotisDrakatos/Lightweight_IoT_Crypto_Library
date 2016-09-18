var forge = require('node-forge');
var fs = require("fs");
var path = require("path");
var dir = './Server';
var pki = forge.pki;
const EventEmitter = require('events');
const util = require('util');

function KeyHandle() {
    EventEmitter.call(this);
    this._format="utf8";
    this.relativeOrAbsolutePathToPublicKey = dir + "/Public.pem"
    this.relativeOrAbsolutePrivateKey = dir + "/Private.pem"
    this.relativeOrAbsoluteCertificate = dir + "/Certificate.pem"
}
util.inherits(KeyHandle, EventEmitter);
KeyHandle.prototype.__proto__ = EventEmitter.prototype;

KeyHandle.prototype.SavePrivateKey = function(privkey) {
    var privpem = pki.privateKeyToPem(privkey);
    fs.writeFile(this.relativeOrAbsolutePrivateKey, privpem, this._format)
    return
};

KeyHandle.prototype.SavePublicKey = function(pubkey) {
    var pubkey = pki.publicKeyToPem(pubkey);
    fs.writeFile(this.relativeOrAbsolutePathToPublicKey, pubkey, this._format)
    return
};

KeyHandle.prototype.SaveCertificate = function(ServerCert) {
    var certpem=ServerCert.Self_Sign_CertTopem();
    fs.writeFile(this.relativeOrAbsoluteCertificate, certpem, this._format)
    return
}
KeyHandle.prototype.loadPrivateKey = function() {
    var absolutePath = path.resolve(this.relativeOrAbsolutePrivateKey);
    var privkey = fs.readFile(absolutePath, this._format);
    return privkey;
};

KeyHandle.prototype.loadPublicKey = function() {
    var absolutePath = path.resolve(this.relativeOrAbsolutePathToPublicKey);
    var publicKey = fs.readFile(absolutePath, this._format);
    return publicKey;
};

KeyHandle.prototype.loadCertificate  = function() {
    var absolutePath = path.resolve(this.relativeOrAbsoluteCertificate);
    var certpem = fs.readFile(absolutePath, this._format);
    return certpem;
};

module.exports = KeyHandle;