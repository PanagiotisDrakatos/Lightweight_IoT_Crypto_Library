
/*var StringFormat='MIIBCgKCAQEArxeCKtE4MeD2xiWmhkjxvK36Cms9fc49edxC3Vf5RYkgBwRwbWmMoQVrWsqs5xq0atGTRLTxUTzhr9Wk1gKxqJIA/dMZ6oo1yeugz94akr91kiCd5Dx6PwunKJocDxa49Fu9HBWDKLqf1A/38SGrjwkxtJyz01OcXVASdiiqujNXxeLYX/UP2iawZ7zSaIgGbtPFa/eQgczHHPIMekOjnzOIC/eXgsw3wxi9xoJ4vC5pIa26pqFPbtfvuvMrzkoHuN2dD+k6YLUfrvGMQaCedDUO1nmsFZKJMnC0/4DJXBO1c2MijojuRr6hfAi0OvdOTDxFyL9Lw/SwCAGkZ4Gq0QIDAQAB';
var forge = require('node-forge');

// base64-decode DER bytes
var certDerBytes = forge.util.decode64(StringFormat);

// parse DER to an ASN.1 object
var obj = forge.asn1.fromDer(certDerBytes);

// convert an ASN.1 SubjectPublicKeyInfo to a Forge public key
var publicKey = forge.pki.publicKeyFromAsn1(obj);

// convert a Forge public key to an ASN.1 SubjectPublicKeyInfo
var subjectPublicKeyInfo = forge.pki.publicKeyToAsn1(publicKey);

console.log(subjectPublicKeyInfo.toString());*/