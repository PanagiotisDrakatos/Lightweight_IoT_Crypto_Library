var forge = require('node-forge');
var path = require("path");
var fs = require("fs");
var Certificate = require('./CertificateFactory');
var pki = forge.pki;
var dir = './Server';

function Keypair(Keyhandle) {
    this.Keyhandle = Keyhandle;
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
        var keypair = pki.rsa.generateKeyPair({
            bits: 2048,
            workers: -1
        });
        this.Keyhandle.SavePublicKey(keypair.publicKey)
        this.Keyhandle.SavePrivateKey(keypair.privateKey)
        var cert = pki.createCertificate();
        var ServerCert = new Certificate(cert, keypair.publicKey,
            keypair.privateKey);
        this.Keyhandle.SaveCertificate(ServerCert);
        console.log(this.Keyhandle._cert)
    }
    else
        console.log("Rsa Already Created!!!!!")
}

/*var SavePrivateKey = function(privkey) {
    var privpem = pki.privateKeyToPem(privkey);
    fs.writeFile(this.relativeOrAbsolutePrivateKey, privpem, "utf8")
    return
};

var SavePublicKey = function(pubkey) {
    var pubkey = pki.publicKeyToPem(pubkey);
    fs.writeFile(this.relativeOrAbsolutePathToPublicKey, pubkey, "utf8")
    return
};

var SaveCertificate = function(cert) {
    fs.writeFile(this.relativeOrAbsoluteCertificate, cert, "utf8")
    return
}

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

module.exports = Keypair();*/

module.exports = Keypair;