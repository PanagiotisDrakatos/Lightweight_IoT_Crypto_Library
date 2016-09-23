'use strict';
var forge = require('node-forge');

exports.SignData = function(Encrypted, PrivateKey) {
    var Hash = 'SHA256'
    var InputEncoding = 'utf8'
    var OutputEncoding = 'base64'
    var _signature = PrivateKey.hashAndSign(Hash, Encrypted, InputEncoding, OutputEncoding);
    return _signature;
}

exports.verifySig = function(Encrypted, publicKey, ClientSignatue) {
    var pki = forge.pki;
    var md = forge.md.sha256.create();
    md.update(Encrypted, 'utf8');
    var decodesignature = forge.util.decode64(ClientSignatue);
    var verified = publicKey.verify(md.digest().bytes(), decodesignature);
    if (verified)
        return true;
    else
        return false;
}