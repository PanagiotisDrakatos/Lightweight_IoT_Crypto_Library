{"changed":true,"filter":false,"title":"IOTransports.js","tooltip":"/IOTransports.js","value":"'use strict';\n\nconst EventEmitter = require('events');\nconst util = require('util');\nvar forge = require('node-forge');\n\nvar jsonToRead = require('./jsonObject.json');\nvar jsonToSend = require('./jsonObject.json');\n\n\nvar RandomGenerators = require('./RandomGenerator');\nvar RsaEncrypts = require(\"./RsaEncrypt\");\nvar FingerPrint = require('./FingerPrint');\nvar ECB = require(\"./AES_ECB\");\nvar CBC = require(\"./AES_CBC\");\nconst HMAC = require('./HmacAlgProvider');\nconst AlgorithmsUse = require('./Allgorithms');\n\nvar Keypair = require('./RsaKeipairs');\nvar KeyHandle = require('./KeyManager')\nvar keystore = new KeyHandle();\nvar server = new Keypair(keystore);\n\nvar _Event = 'DHSessionHandshake';\nvar Generator = '';\nvar _ClientSymmetricKey;\nvar IntegrityKey = require('./DHintegrityKey')\nvar integritykey = new IntegrityKey();\nvar CipherKey = require('./DHCipherKey')\nvar cipherkey = new CipherKey();\nvar Algorithms = new AlgorithmsUse();\n\nvar count = 0;\n\nfunction BasicProtocolEmmitter() {\n    EventEmitter.call(this);\n    BasicProtocolEmmitter.IntializeCallbacks();\n    Generator = new RandomGenerators();\n    this.dataToSend = '';\n}\nutil.inherits(BasicProtocolEmmitter, EventEmitter);\n\nBasicProtocolEmmitter.prototype.__proto__ = EventEmitter.prototype;\n\n\n\nBasicProtocolEmmitter.IntializeCallbacks = function() {\n    BasicProtocolEmmitter.prototype.removeAllListeners();\n    BasicProtocolEmmitter.prototype.on(_Event, ReceivePlainMessage);\n}\n\n\n\nBasicProtocolEmmitter.prototype.send = function() {\n    // this.ReceivedData = data;\n    BasicProtocolEmmitter.prototype.emit(_Event);\n    return JSON.stringify(jsonToSend);\n}\nBasicProtocolEmmitter.prototype.Receive = function(ObjToRead) {\n    // this.ReceivedData = data;\n    BasicProtocolEmmitter.prototype.emit(_Event, ObjToRead);\n    return JSON.stringify(jsonToSend);\n}\n\nvar ReceivePlainMessage = function(ObjToRead) {\n    jsonToRead = JSON.parse(ObjToRead);\n    if (jsonToRead.PlainMessage != \"ClientHello\" ||\n        jsonToRead.PseudoNumber != Generator.pseudorandom())\n        new Error('Not Valid Protocol to Start');\n\n    BasicProtocolEmmitter.prototype.on(_Event, SendCertificate);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceivePlainMessage);\n};\n\n\nvar SendCertificate = function() {\n    clear();\n    jsonToSend.PlainMessage = \"ServerHello\";\n    jsonToSend.PseudoNumber = Generator.pseudorandom();\n    jsonToSend.CookieServer = Generator.CookieServer();\n    jsonToSend.CertPemFormat = keystore.loadCertificate();\n    BasicProtocolEmmitter.prototype.on(_Event, RepetitionPrevention);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, SendCertificate);\n};\n\nvar RepetitionPrevention = function(ObjToRead) {\n    jsonToRead = JSON.parse(ObjToRead);\n\n    if (jsonToRead.PlainMessage != \"Resend\" ||\n        jsonToRead.CookieServer != Generator.CookieServer() ||\n        jsonToRead.PseudoNumber != Generator.pseudorandom())\n        new Error('Can Not Valid Client Possible Replay Attack');\n\n    BasicProtocolEmmitter.prototype.on(_Event, ReceivePublicValue);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, RepetitionPrevention);\n};\n\nvar ReceivePublicValue = function(ObjToRead) {\n    jsonToRead = JSON.parse(ObjToRead);\n\n    if (jsonToRead.PseudoNumber != Generator.pseudorandom())\n        new Error('Can Not Valid Client Possible Replay Attack');\n\n    var ClientPublicNumber = RsaEncrypts.RsaDeCryption(keystore.loadPrivateKey(), jsonToRead.ClientEncryptedPrimeNumber);\n    Generator.SessionGenerator(ClientPublicNumber);\n\n    BasicProtocolEmmitter.prototype.on(_Event, SendPublicValue);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceivePublicValue);\n};\n\nvar SendPublicValue = function() {\n    //clear();\n\n    var serverprime = Generator.PublicPrimeNumber();\n    jsonToSend.ServerPrimeNumber = serverprime;\n    jsonToSend.PseudoNumber = Generator.pseudorandom();\n    console.log(Generator.DHKeyExchange())\n        //console.log(\"session keys is :\" + Generator.DHKeyExchange());\n    BasicProtocolEmmitter.prototype.on(_Event, ReceiveCipherSuites);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, SendPublicValue);\n}\n\nvar ReceiveCipherSuites = function(ObjToRead) {\n\n    jsonToRead = JSON.parse(ObjToRead);\n    if (jsonToRead.PseudoNumber != Generator.pseudorandom())\n        new Error('Can Not Valid Client Possible Replay Attack');\n\n    integritykey.GenerateIntegrityKey(Generator.DHKeyExchange());\n    var joiner = (jsonToRead.CipherSuites).split(\"|\");\n    var Chiphers = joiner[0].split(\",\");\n    var Digests = joiner[1].split(\",\");\n    var CurrentDiggests = joiner[2].split(\",\");\n\n    if (CurrentDiggests.indexOf(\"Hmac\"))\n        CurrentDiggests = CurrentDiggests.toString().replace(/Hmac/i, '');\n\n    if (!HMAC.HmacVerify(jsonToRead.CipherSuites,\n            integritykey.returnIntegrityKey(), jsonToRead.HmacHash, CurrentDiggests))\n        new Error('Integrity Of Message can not be verified');\n    Algorithms.ChooserCipher(Chiphers);\n    Algorithms.ChooserHash(Digests);\n    Algorithms.SetCurrentHash(CurrentDiggests);\n    BasicProtocolEmmitter.prototype.on(_Event, SendCipherSuites);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceiveCipherSuites);\n};\n\nvar SendCipherSuites = function() {\n    clear();\n\n    var Algo = '';\n    Algo = Algo.concat(Algorithms.returnCipherAlgorithm(), '|');\n    Algo = Algo.concat(Algorithms.returnHashAlgorithm(), '|');\n\n    jsonToSend.CipherSuites = Algo;\n    jsonToSend.PseudoNumber = Generator.pseudorandom();\n    jsonToSend.HmacHash = HMAC.HmacSign(jsonToSend.CipherSuites, integritykey.returnIntegrityKey(), Algorithms.returnCurrentHash());\n\n    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, SendCipherSuites);\n};\n\nvar ReceiveDHEncryptedMessage = function(ObjToRead) {\n    jsonToRead = JSON.parse(ObjToRead);\n    console.log(jsonToRead.EncryptedMessage);\n    if (!HMAC.HmacVerify(jsonToRead.EncryptedMessage, integritykey.returnIntegrityKey(),\n            jsonToRead.HmacHash, Algorithms.returnHashAlgorithm()))\n        new Error('Integrity Of Client Key canot be verified');\n\n    cipherkey.GenerateChipherKey(Generator.DHKeyExchange());\n    var _DecryptedMessage = CBC.AesDecryption(jsonToRead.EncryptedMessage, cipherkey.returnChipherKey());\n    console.log('Clients says ' + _DecryptedMessage);\n    BasicProtocolEmmitter.prototype.on(_Event, SendDHEncryptedMessage);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, ReceiveDHEncryptedMessage);\n\n};\n\nvar SendDHEncryptedMessage = function(ObjToRead) {\n    clear();\n    var _EncryptedMessage = CBC.AesEncryption(new Buffer(\"Helloclient\" + count++), cipherkey.returnChipherKey());\n    var _Mac = HMAC.HmacSign(_EncryptedMessage, integritykey.returnIntegrityKey(), Algorithms.returnCurrentHash());\n    var _signature = FingerPrint.SignData(_EncryptedMessage, keystore.loadPrivateKey())\n\n    jsonToSend.EncryptedMessage = _EncryptedMessage;\n    jsonToSend.HmacHash = _Mac;\n    jsonToSend.FingerPrint = _signature;\n\n    BasicProtocolEmmitter.prototype.on(_Event, ReceiveDHEncryptedMessage);\n    BasicProtocolEmmitter.prototype.removeListener(_Event, SendDHEncryptedMessage);\n};\n\nfunction clear() {\n    delete jsonToSend['PlainMessage'];\n    delete jsonToSend['CookieServer'];\n    delete jsonToSend['CertPemFormat'];\n    delete jsonToSend['PseudoNumber'];\n    delete jsonToSend['ClientEncryptedPrimeNumber'];\n    delete jsonToSend['ServerPrimeNumber'];\n    delete jsonToSend['EncryptedMessage'];\n    delete jsonToSend['FingerPrint'];\n    delete jsonToSend['HmacHash'];\n}\n\nmodule.exports = BasicProtocolEmmitter;","undoManager":{"mark":87,"position":100,"stack":[[{"start":{"row":169,"column":73},"end":{"row":169,"column":74},"action":"remove","lines":["."],"id":1204}],[{"start":{"row":168,"column":60},"end":{"row":169,"column":0},"action":"insert","lines":["",""],"id":1213},{"start":{"row":169,"column":0},"end":{"row":169,"column":4},"action":"insert","lines":["    "]}],[{"start":{"row":169,"column":4},"end":{"row":169,"column":5},"action":"insert","lines":["c"],"id":1214}],[{"start":{"row":169,"column":5},"end":{"row":169,"column":6},"action":"insert","lines":["o"],"id":1215}],[{"start":{"row":169,"column":6},"end":{"row":169,"column":7},"action":"insert","lines":["n"],"id":1216},{"start":{"row":169,"column":7},"end":{"row":169,"column":8},"action":"insert","lines":["s"]}],[{"start":{"row":169,"column":8},"end":{"row":169,"column":9},"action":"insert","lines":["o"],"id":1217}],[{"start":{"row":169,"column":9},"end":{"row":169,"column":10},"action":"insert","lines":["l"],"id":1218}],[{"start":{"row":169,"column":10},"end":{"row":169,"column":11},"action":"insert","lines":["e"],"id":1219}],[{"start":{"row":169,"column":11},"end":{"row":169,"column":12},"action":"insert","lines":["."],"id":1220}],[{"start":{"row":169,"column":12},"end":{"row":169,"column":13},"action":"insert","lines":["l"],"id":1221}],[{"start":{"row":169,"column":13},"end":{"row":169,"column":14},"action":"insert","lines":["o"],"id":1222}],[{"start":{"row":169,"column":14},"end":{"row":169,"column":15},"action":"insert","lines":["g"],"id":1223}],[{"start":{"row":169,"column":15},"end":{"row":169,"column":17},"action":"insert","lines":["()"],"id":1224}],[{"start":{"row":169,"column":16},"end":{"row":169,"column":43},"action":"insert","lines":["jsonToRead.EncryptedMessage"],"id":1225}],[{"start":{"row":169,"column":44},"end":{"row":169,"column":45},"action":"insert","lines":[";"],"id":1226}],[{"start":{"row":169,"column":45},"end":{"row":170,"column":0},"action":"insert","lines":["",""],"id":1227},{"start":{"row":170,"column":0},"end":{"row":170,"column":4},"action":"insert","lines":["    "]}],[{"start":{"row":170,"column":4},"end":{"row":170,"column":17},"action":"insert","lines":["AesDecryption"],"id":1228}],[{"start":{"row":169,"column":3},"end":{"row":170,"column":17},"action":"remove","lines":[" console.log(jsonToRead.EncryptedMessage);","    AesDecryption"],"id":1229}],[{"start":{"row":169,"column":2},"end":{"row":169,"column":3},"action":"remove","lines":[" "],"id":1230}],[{"start":{"row":169,"column":1},"end":{"row":169,"column":2},"action":"remove","lines":[" "],"id":1231}],[{"start":{"row":169,"column":0},"end":{"row":169,"column":1},"action":"remove","lines":[" "],"id":1232}],[{"start":{"row":168,"column":60},"end":{"row":169,"column":0},"action":"remove","lines":["",""],"id":1233}],[{"start":{"row":178,"column":28},"end":{"row":178,"column":31},"action":"remove","lines":["CBC"],"id":1239},{"start":{"row":178,"column":28},"end":{"row":178,"column":29},"action":"insert","lines":["E"]}],[{"start":{"row":178,"column":29},"end":{"row":178,"column":30},"action":"insert","lines":["C"],"id":1240}],[{"start":{"row":178,"column":28},"end":{"row":178,"column":30},"action":"remove","lines":["EC"],"id":1241},{"start":{"row":178,"column":28},"end":{"row":178,"column":31},"action":"insert","lines":["ECB"]}],[{"start":{"row":169,"column":28},"end":{"row":169,"column":32},"action":"remove","lines":["CBC."],"id":1242},{"start":{"row":169,"column":28},"end":{"row":169,"column":32},"action":"insert","lines":["ECB."]}],[{"start":{"row":169,"column":28},"end":{"row":169,"column":31},"action":"remove","lines":["ECB"],"id":1243}],[{"start":{"row":169,"column":27},"end":{"row":169,"column":28},"action":"remove","lines":[" "],"id":1244}],[{"start":{"row":169,"column":27},"end":{"row":169,"column":28},"action":"insert","lines":["c"],"id":1245}],[{"start":{"row":169,"column":27},"end":{"row":169,"column":28},"action":"remove","lines":["c"],"id":1246}],[{"start":{"row":169,"column":27},"end":{"row":169,"column":28},"action":"insert","lines":["C"],"id":1247}],[{"start":{"row":169,"column":28},"end":{"row":169,"column":29},"action":"insert","lines":["B"],"id":1248}],[{"start":{"row":169,"column":29},"end":{"row":169,"column":30},"action":"insert","lines":["C"],"id":1249}],[{"start":{"row":178,"column":30},"end":{"row":178,"column":31},"action":"remove","lines":["B"],"id":1257}],[{"start":{"row":178,"column":29},"end":{"row":178,"column":30},"action":"remove","lines":["C"],"id":1258}],[{"start":{"row":178,"column":28},"end":{"row":178,"column":29},"action":"remove","lines":["E"],"id":1259}],[{"start":{"row":178,"column":28},"end":{"row":178,"column":29},"action":"insert","lines":["C"],"id":1260}],[{"start":{"row":178,"column":29},"end":{"row":178,"column":30},"action":"insert","lines":["B"],"id":1261}],[{"start":{"row":178,"column":30},"end":{"row":178,"column":31},"action":"insert","lines":["C"],"id":1262}],[{"start":{"row":31,"column":0},"end":{"row":32,"column":0},"action":"insert","lines":["",""],"id":1263}],[{"start":{"row":32,"column":0},"end":{"row":32,"column":1},"action":"insert","lines":["V"],"id":1264}],[{"start":{"row":32,"column":1},"end":{"row":32,"column":2},"action":"insert","lines":["A"],"id":1265}],[{"start":{"row":32,"column":2},"end":{"row":32,"column":3},"action":"insert","lines":["R"],"id":1266}],[{"start":{"row":32,"column":3},"end":{"row":32,"column":4},"action":"insert","lines":[" "],"id":1267}],[{"start":{"row":32,"column":4},"end":{"row":32,"column":5},"action":"insert","lines":["C"],"id":1268}],[{"start":{"row":32,"column":5},"end":{"row":32,"column":6},"action":"insert","lines":["O"],"id":1269}],[{"start":{"row":32,"column":6},"end":{"row":32,"column":7},"action":"insert","lines":["U"],"id":1270}],[{"start":{"row":32,"column":7},"end":{"row":32,"column":8},"action":"insert","lines":["N"],"id":1271}],[{"start":{"row":32,"column":8},"end":{"row":32,"column":9},"action":"insert","lines":["T"],"id":1272}],[{"start":{"row":32,"column":8},"end":{"row":32,"column":9},"action":"remove","lines":["T"],"id":1273}],[{"start":{"row":32,"column":7},"end":{"row":32,"column":8},"action":"remove","lines":["N"],"id":1274}],[{"start":{"row":32,"column":6},"end":{"row":32,"column":7},"action":"remove","lines":["U"],"id":1275}],[{"start":{"row":32,"column":5},"end":{"row":32,"column":6},"action":"remove","lines":["O"],"id":1276}],[{"start":{"row":32,"column":4},"end":{"row":32,"column":5},"action":"remove","lines":["C"],"id":1277}],[{"start":{"row":32,"column":3},"end":{"row":32,"column":4},"action":"remove","lines":[" "],"id":1278}],[{"start":{"row":32,"column":2},"end":{"row":32,"column":3},"action":"remove","lines":["R"],"id":1279}],[{"start":{"row":32,"column":1},"end":{"row":32,"column":2},"action":"remove","lines":["A"],"id":1280}],[{"start":{"row":32,"column":0},"end":{"row":32,"column":1},"action":"remove","lines":["V"],"id":1281}],[{"start":{"row":32,"column":0},"end":{"row":32,"column":1},"action":"insert","lines":["v"],"id":1282}],[{"start":{"row":32,"column":1},"end":{"row":32,"column":2},"action":"insert","lines":["a"],"id":1283}],[{"start":{"row":32,"column":2},"end":{"row":32,"column":3},"action":"insert","lines":["r"],"id":1284}],[{"start":{"row":32,"column":3},"end":{"row":32,"column":4},"action":"insert","lines":[" "],"id":1285}],[{"start":{"row":32,"column":4},"end":{"row":32,"column":5},"action":"insert","lines":["c"],"id":1286}],[{"start":{"row":32,"column":5},"end":{"row":32,"column":6},"action":"insert","lines":["o"],"id":1287}],[{"start":{"row":32,"column":6},"end":{"row":32,"column":7},"action":"insert","lines":["u"],"id":1288}],[{"start":{"row":32,"column":7},"end":{"row":32,"column":8},"action":"insert","lines":["n"],"id":1289}],[{"start":{"row":32,"column":8},"end":{"row":32,"column":9},"action":"insert","lines":["t"],"id":1290}],[{"start":{"row":32,"column":9},"end":{"row":32,"column":10},"action":"insert","lines":["="],"id":1291}],[{"start":{"row":32,"column":10},"end":{"row":32,"column":11},"action":"insert","lines":["0"],"id":1292}],[{"start":{"row":32,"column":11},"end":{"row":32,"column":12},"action":"insert","lines":[";"],"id":1293}],[{"start":{"row":179,"column":70},"end":{"row":179,"column":71},"action":"insert","lines":["+"],"id":1294}],[{"start":{"row":179,"column":71},"end":{"row":179,"column":72},"action":"insert","lines":["c"],"id":1295}],[{"start":{"row":179,"column":72},"end":{"row":179,"column":73},"action":"insert","lines":["o"],"id":1296}],[{"start":{"row":179,"column":73},"end":{"row":179,"column":74},"action":"insert","lines":["u"],"id":1297}],[{"start":{"row":179,"column":74},"end":{"row":179,"column":75},"action":"insert","lines":["n"],"id":1298}],[{"start":{"row":179,"column":75},"end":{"row":179,"column":76},"action":"insert","lines":["t"],"id":1299}],[{"start":{"row":179,"column":76},"end":{"row":179,"column":77},"action":"insert","lines":["+"],"id":1300}],[{"start":{"row":179,"column":77},"end":{"row":179,"column":78},"action":"insert","lines":["+"],"id":1301}],[{"start":{"row":113,"column":3},"end":{"row":113,"column":4},"action":"insert","lines":["/"],"id":1302}],[{"start":{"row":113,"column":4},"end":{"row":113,"column":5},"action":"insert","lines":["/"],"id":1303}],[{"start":{"row":114,"column":4},"end":{"row":114,"column":5},"action":"insert","lines":["/"],"id":1304}],[{"start":{"row":114,"column":5},"end":{"row":114,"column":6},"action":"insert","lines":["/"],"id":1305}],[{"start":{"row":111,"column":4},"end":{"row":111,"column":5},"action":"insert","lines":["/"],"id":1306}],[{"start":{"row":111,"column":5},"end":{"row":111,"column":6},"action":"insert","lines":["/"],"id":1307}],[{"start":{"row":115,"column":3},"end":{"row":115,"column":4},"action":"insert","lines":["/"],"id":1308}],[{"start":{"row":115,"column":4},"end":{"row":115,"column":5},"action":"insert","lines":["/"],"id":1309}],[{"start":{"row":116,"column":3},"end":{"row":116,"column":4},"action":"insert","lines":["/"],"id":1310}],[{"start":{"row":116,"column":4},"end":{"row":116,"column":5},"action":"insert","lines":["/"],"id":1311}],[{"start":{"row":116,"column":4},"end":{"row":116,"column":5},"action":"remove","lines":["/"],"id":1312}],[{"start":{"row":116,"column":3},"end":{"row":116,"column":4},"action":"remove","lines":["/"],"id":1313}],[{"start":{"row":115,"column":5},"end":{"row":115,"column":6},"action":"remove","lines":[" "],"id":1314}],[{"start":{"row":115,"column":4},"end":{"row":115,"column":5},"action":"remove","lines":["/"],"id":1315}],[{"start":{"row":115,"column":3},"end":{"row":115,"column":4},"action":"remove","lines":["/"],"id":1316}],[{"start":{"row":114,"column":6},"end":{"row":114,"column":7},"action":"remove","lines":["j"],"id":1317}],[{"start":{"row":114,"column":5},"end":{"row":114,"column":6},"action":"remove","lines":["/"],"id":1318}],[{"start":{"row":114,"column":4},"end":{"row":114,"column":5},"action":"remove","lines":["/"],"id":1319}],[{"start":{"row":113,"column":5},"end":{"row":113,"column":6},"action":"remove","lines":[" "],"id":1320}],[{"start":{"row":113,"column":4},"end":{"row":113,"column":5},"action":"remove","lines":["/"],"id":1321}],[{"start":{"row":113,"column":3},"end":{"row":113,"column":4},"action":"remove","lines":["/"],"id":1322}],[{"start":{"row":114,"column":4},"end":{"row":114,"column":5},"action":"insert","lines":["j"],"id":1323}],[{"start":{"row":13,"column":7},"end":{"row":13,"column":8},"action":"insert","lines":[" "],"id":1324},{"start":{"row":14,"column":7},"end":{"row":14,"column":8},"action":"insert","lines":[" "]},{"start":{"row":32,"column":9},"end":{"row":32,"column":10},"action":"insert","lines":[" "]},{"start":{"row":32,"column":11},"end":{"row":32,"column":12},"action":"insert","lines":[" "]},{"start":{"row":113,"column":3},"end":{"row":113,"column":4},"action":"insert","lines":[" "]},{"start":{"row":115,"column":0},"end":{"row":115,"column":1},"action":"insert","lines":[" "]},{"start":{"row":157,"column":0},"end":{"row":157,"column":2},"action":"remove","lines":["  "]},{"start":{"row":170,"column":27},"end":{"row":170,"column":28},"action":"insert","lines":[" "]},{"start":{"row":179,"column":70},"end":{"row":179,"column":71},"action":"insert","lines":[" "]},{"start":{"row":179,"column":72},"end":{"row":179,"column":73},"action":"insert","lines":[" "]},{"start":{"row":180,"column":12},"end":{"row":180,"column":13},"action":"insert","lines":[" "]},{"start":{"row":180,"column":14},"end":{"row":180,"column":15},"action":"insert","lines":[" "]},{"start":{"row":186,"column":0},"end":{"row":186,"column":4},"action":"remove","lines":["    "]}]]},"ace":{"folds":[],"scrolltop":1380,"scrollleft":0,"selection":{"start":{"row":114,"column":47},"end":{"row":114,"column":47},"isBackwards":false},"options":{"guessTabSize":true,"useWrapMode":false,"wrapToView":true},"firstLineState":{"row":97,"state":"start","mode":"ace/mode/javascript"}},"timestamp":1474899535161}