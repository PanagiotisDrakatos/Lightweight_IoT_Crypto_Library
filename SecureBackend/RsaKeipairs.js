var forge = require('node-forge');
var path = require("path");
var fs = require("fs");
var pki = forge.pki;


function Keypair() {
    this.relativeOrAbsolutePathToPublicKey = "./Server/Public.pem"
    this.relativeOrAbsolutePrivateKey = "./Server/Private.pem"
    var keypair = pki.rsa.generateKeyPair({
        bits: 2048,
        workers: 2
    });
    var cert = pki.createCertificate();
    SavePublicKey(keypair.publicKey)
    SavePrivateKey(keypair.privateKey)
}

var SavePrivateKey = function(privkey) {
    var privpem = pki.privateKeyToPem(privkey);
    fs.writeFile(this.relativeOrAbsolutePrivateKey, privpem, "utf8")
    return
};

var SavePublicKey = function(pubkey) {
    var pubkey = pki.publicKeyToPem(pubkey);
    fs.writeFile(this.relativeOrAbsolutePathToPublicKey, pubkey, "utf8")
    return
};

Keypair.prototype.loadPrivateKey = function() {
    var absolutePath = path.resolve(this.relativeOrAbsolutePrivateKey);
    var privkey = fs.readFileSync(absolutePath, "utf8");
    return privkey;
};

Keypair.prototype.loadPublicKey = function() {
    var absolutePath = path.resolve(this.relativeOrAbsolutePathToPublicKey);
    var publicKey = fs.readFileASync(absolutePath, "utf8");
    return publicKey;
};

module.exports = Keypair();