'use strict';

const crypto = require('crypto');
const HMAC = require('./HmacAlgProvider');

var AESalgoProv = 'aes-128-ecb';

exports.AesEncryption = function(Plaintext, SecurePassword) {
    var cipher = crypto.createCipher(AESalgoProv, SecurePassword);
    var encrypted = cipher.update(Plaintext, 'utf-8', 'base64');
    encrypted += cipher.final('base64');

    var Mac = HMAC.HmacSha256Sign(encrypted, SecurePassword);

    return {
        Encrypted: encrypted,
        Hmac: Mac
    };
};
exports.AesDecryption = function(EncryptedText, SecurePassword, Mac) {
    if (!HMAC.HmacSha256Verify(EncryptedText, SecurePassword, Mac)) {
        return 'Integrity Of Message Cannot Be Verified';
    }
    var decipher = crypto.createDecipher(AESalgoProv, SecurePassword);
    var decrypted = decipher.update(EncryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};