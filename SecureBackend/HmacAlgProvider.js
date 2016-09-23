'use strict';

const crypto = require('crypto');
var forge = require('node-forge');

exports.HmacSign = function(Data, key,algo) {
    var sign = crypto.createHmac(algo,new Buffer(key,'utf8')).update(Data).digest('base64');
    return sign;
}
exports.HmacVerify = function(Data,key, HmacMsg,algo) {

    var ServerHmacSign = exports.HmacSign(Data, key,algo);
    if (HmacMsg == ServerHmacSign) {
        console.log("Integrity verified successfully");
        return true;
    }
    else {
        console.log("Integrity Of Message can not be verified");
        return false;
    }

}