'use strict';

var PromiseInspection = require('bluebird').Promise;
var fs = PromiseInspection.promisifyAll(require('fs'));
var path = require('path');
var ursa = require('ursa');
var mkdirpAsync = PromiseInspection.promisify(require('mkdirp'));

module.exports.keypair = Keypair;

function Keypair(pathname) {
    var key = ursa.generatePrivateKey(2048, 65537);
    var privpem = key.toPrivatePem();
    var pubpem = key.toPublicPem();
    var privkey = path.join(pathname, 'privkey.pem');
    var pubkey = path.join(pathname, 'pubkey.pem');

    return mkdirpAsync(pathname).then(function() {
        return PromiseInspection.all([
            fs.writeFileAsync(privkey, privpem, 'ascii'), fs.writeFileAsync(pubkey, pubpem, 'ascii')
        ]);
    }).then(function() {
        return key;
    });
}

if (require.main === module) {
    return PromiseInspection.all([
        Keypair('RsaKeyPairs')
    ]).then(function(keys) {
        console.log('generated %d keypairs', keys.length);
    });
}

exports.StoreClientPublic = function(pubpem) {
    PromiseInspection.all([
        fs.writeFileAsync('./Client/ClientPublicpem.pem', pubpem, 'utf8')
    ]);
}
