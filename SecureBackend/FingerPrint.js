'use strict';
const crypto = require('crypto');

exports.SignData = function(Encrypted, PrivateKey) {
    var privateKey = PrivateKey.toString('base64');
    var signature = crypto.createSign('RSA-SHA256');
    signature.update(Encrypted);
    var base64encoded = signature.sign(privateKey, 'base64');
    return base64encoded;
}

