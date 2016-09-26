'use strict';

const crypto = require('crypto');
const HMAC = require('./HmacAlgProvider');

var AESalgoProv = 'aes-128-ecb';

exports.AesEncryption = function(Plaintext, key) {
    var cipher = crypto.createCipher(AESalgoProv, new Buffer(key,'utf8'));
    var encrypted = cipher.update(Plaintext, 'utf-8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
};
exports.AesDecryption = function(EncryptedText, key) {
    var decipher = crypto.createDecipher(AESalgoProv, new Buffer(key,'utf8'));
    var decrypted = decipher.update(EncryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};