'use strict';
var forge = require('node-forge');

exports.RsaEncryption = function(PublicPem, Plaintext) {
    var md = forge.md.sha1.create();
    md.update('sign this', 'utf8');
    var bytes = md.digest().getBytes();
    var PublicKey = forge.pki.publicKeyFromPem(PublicPem);
    var encrypted = PublicKey.encrypt(bytes);
    console.log('EncryptedMessage ' + encrypted + '\n');
    return encrypted;
    //return Buffer.concat(encrypted).toString('base64');
};

exports.RsaDeCryption = function(PrivPem,encoded) {
    console.log('Decrypt with Server Private Key');
    var PrivateKey = forge.pki.privateKeyFromPem(PrivPem);
    var str = forge.util.decode64(encoded);
    var decrypted = PrivateKey.decrypt(str);
    console.log('DecryptedMessage ', decrypted, '\n');
    return decrypted;
};