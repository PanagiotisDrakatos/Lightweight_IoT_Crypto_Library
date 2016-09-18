var forge = require('node-forge');
const EventEmitter = require('events');
const util = require('util');

function Certificate(cert, pubkey, privkey) {
    EventEmitter.call(this);
    this._cert = cert;
    this.GenerateValideCert(pubkey, privkey);
}
util.inherits(Certificate, EventEmitter);
Certificate.prototype.__proto__ = EventEmitter.prototype;

Certificate.prototype.GenerateValideCert = function(pubkey, privkey) {
    this._cert.publicKey = pubkey;
    this._cert.serialNumber = '01';
    this._cert.validity.notBefore = new Date();
    this._cert.validity.notAfter = new Date();
    this._cert.validity.notAfter.setFullYear(this._cert.validity.notBefore.getFullYear() + 1);
    var attrs = [{
        name: 'commonName',
        value: 'example.org'
    }, {
        name: 'countryName',
        value: 'GR'
    }, {
        shortName: 'ST',
        value: 'Athens'
    }, {
        name: 'localityName',
        value: 'Athens'
    }, {
        name: 'organizationName',
        value: 'Test'
    }, {
        shortName: 'OU',
        value: 'Test'
    }];
    this._cert.setSubject(attrs);
    // alternatively set subject from a csr
    //cert.setSubject(csr.subject.attributes);
    this._cert.setIssuer(attrs);
    this._cert.setExtensions([{
        name: 'basicConstraints',
        cA: true
    }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    }, {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true
    }, {
        name: 'nsCertType',
        client: true,
        server: true,
        email: true,
        objsign: true,
        sslCA: true,
        emailCA: true,
        objCA: true
    }, {
        name: 'subjectAltName',
        altNames: [{
            type: 6, // URI
            value: 'http://example.org/webid#me'
        }, {
            type: 7, // IP
            ip: '127.0.0.1'
        }]
    }, {
        name: 'subjectKeyIdentifier'
    }]);
    this._cert.sign(privkey);
};


Certificate.prototype.Self_Sign_CertTopem = function() {
    var pem = forge.pki.certificateToPem(this._cert);
    return pem;
};
module.exports = Certificate;