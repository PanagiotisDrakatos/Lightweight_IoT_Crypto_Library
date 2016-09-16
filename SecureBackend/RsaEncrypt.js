'use strict';

var ursa = require('ursa');
var padding = ursa.RSA_PKCS1_PADDING;

exports.RsaEncryption = function(PublicKey, Plaintext) {
    console.log('Encrypt with Server Publickey ' + Plaintext);
    var encrypted = PublicKey.encrypt(Plaintext, 'utf8', 'base64', padding);
    console.log('EncryptedMessage ' + encrypted + '\n');
    return encrypted;
    //return Buffer.concat(encrypted).toString('base64');
};

exports.RsaDeCryption = function(Encryptedtext, PrivateKey) {
    console.log('Decrypt with Server Private Key');
    var decrypted = PrivateKey.decrypt(Encryptedtext, 'base64', 'utf8', padding);
    console.log('DecryptedMessage ', decrypted, '\n');
    return decrypted;
};