var KeyHandle = require('./KeyManager')
var keystore = new KeyHandle();
console.log(keystore.loadPublicKey());