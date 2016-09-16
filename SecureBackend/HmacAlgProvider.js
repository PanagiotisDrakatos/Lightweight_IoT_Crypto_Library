'use strict';

const crypto = require('crypto');

exports.HmacSha256Sign = function(Encrypted, key) {
    const hash = crypto.createHmac('sha256', key)
        .update(Encrypted)
        .digest('base64');
    return hash;
}
exports.HmacSha256Verify = function(Encrypted, key, HmacMsg) {

    var ServerHmacSign = exports.HmacSha256Sign(Encrypted, key);
    if (HmacMsg==ServerHmacSign) {
        console.log("Integrity verified successfully");
        return true;
    }
    else {
        console.log("Integrity Of Message can not be verified");
        return false;
    }

}