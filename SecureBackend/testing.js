var CipherKey = require('./DHintegrityKey')
var encrypt = require('./AES_ECB')
var CBC = require('./AES_CBC')
var key = new CipherKey();
key.GenerateIntegrityKey("9563257376919490517748861543691931776658267302089166526532367778950459658197722322112");
var bytekey = key.returnIntegrityKey()
console.log(bytekey.length)
var KeyHandle = require('./KeyManager')
var FingerPrint = require('./FingerPrint');
var keystore = new KeyHandle();
var forge = require('node-forge');

var str = "123, 124, 234,252";
var arr = str.split(",");
console.log(arr[0] + arr[1]);

var anyString = 'Brave new world';

console.log('The index of the first w from the beginning is ' + anyString.indexOf('w'));


//var data = FingerPrint.SignData("asdasdsa", keystore.loadPrivateKey())
//console.log(data);

var encryptdf=CBC.AesEncryption(new Buffer("sddsa"),"key");
console.log(encryptdf)
var decry=CBC.AesDecryption("y8U1LHbkQ+U7eiFhufs30Q==","key")
console.log(decry);



