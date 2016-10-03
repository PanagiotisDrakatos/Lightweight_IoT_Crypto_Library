var forge = require('node-forge');
var fs = require("fs");
var path = require("path");
var dir = './Server';
var pki = forge.pki;
const EventEmitter = require('events');
const util = require('util');

function KeyHandle() {
    EventEmitter.call(this);
    this._format = "utf8";
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
    var certpem = ServerCert.Self_Sign_CertTopem();
    fs.writeFile(this.relativeOrAbsoluteCertificate, certpem, this._format)
    return
}
KeyHandle.prototype.loadPrivateKey = function() {
    var privkey = fs.readFileSync(this.relativeOrAbsolutePrivateKey, this._format);
    return privkey;
};

KeyHandle.prototype.loadPublicKey = function() {
    var publicKey = fs.readFileSync(this.relativeOrAbsolutePathToPublicKey, this._format);
    return publicKey;
};

KeyHandle.prototype.loadCertificate = function() {
    var certpem = fs.readFileSync(this.relativeOrAbsoluteCertificate, this._format);
    var cert = forge.pki.certificateFromPem(certpem);
    var asn1Cert = forge.pki.certificateToAsn1(cert);
    var der1 = forge.asn1.toDer(asn1Cert).getBytes();
    var encoded= forge.util.encode64(der1);
    return encoded;
};

module.exports = KeyHandle;