'use strict';
var forge = require('node-forge');

exports.SignData = function(Encrypted, PrivateKey) {
    var InputEncoding = 'utf8'
    var md = forge.md.sha1.create();
    md.update(Encrypted, InputEncoding);
    var privateKey = forge.pki.privateKeyFromPem(PrivateKey);
    var _signature = privateKey.sign(md);
    var base64encoded = forge.util.encode64(_signature);
    return base64encoded;
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