'use strict';

const crypto = require('crypto');

var AESalgoProv = 'aes-128-cbc';
const IV= Buffer.from([0x15, 0x14, 0x13, 0x12, 0x11,
            0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]);
            
exports.AesEncryption = function(data, key) {
    var encodeKey = crypto.createHash('md5').update(new Buffer(key), 'utf-8').digest();
    var cipher = crypto.createCipheriv(AESalgoProv, encodeKey, IV);
    var encrypted = cipher.update(data, 'utf-8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
};
exports.AesDecryption = function(encryptedata, key) {
    var encodeKey = crypto.createHash('md5').update(new Buffer(key), 'utf-8').digest();
    var decipher = crypto.createDecipheriv(AESalgoProv, encodeKey, IV);
    var decoded  = decipher.update(encryptedata,'base64', 'utf8');

    decoded += decipher.final('utf8');
    return decoded;
};