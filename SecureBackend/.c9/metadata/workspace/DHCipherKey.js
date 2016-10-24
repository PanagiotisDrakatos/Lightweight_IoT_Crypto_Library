{"filter":false,"title":"DHCipherKey.js","tooltip":"/DHCipherKey.js","ace":{"folds":[],"scrolltop":0,"scrollleft":0,"selection":{"start":{"row":36,"column":69},"end":{"row":36,"column":69},"isBackwards":false},"options":{"guessTabSize":true,"useWrapMode":false,"wrapToView":true},"firstLineState":0},"hash":"e6af5db6edc2003625e8546699e2a5c90addd78b","undoManager":{"mark":100,"position":100,"stack":[[{"start":{"row":29,"column":25},"end":{"row":29,"column":26},"action":"insert","lines":["."],"id":571}],[{"start":{"row":29,"column":26},"end":{"row":29,"column":27},"action":"insert","lines":["T"],"id":572}],[{"start":{"row":29,"column":27},"end":{"row":29,"column":28},"action":"insert","lines":["O"],"id":573}],[{"start":{"row":29,"column":27},"end":{"row":29,"column":28},"action":"remove","lines":["O"],"id":574}],[{"start":{"row":29,"column":26},"end":{"row":29,"column":27},"action":"remove","lines":["T"],"id":575}],[{"start":{"row":29,"column":26},"end":{"row":29,"column":27},"action":"insert","lines":["T"],"id":576}],[{"start":{"row":29,"column":27},"end":{"row":29,"column":28},"action":"insert","lines":["O"],"id":577}],[{"start":{"row":29,"column":27},"end":{"row":29,"column":28},"action":"remove","lines":["O"],"id":578}],[{"start":{"row":29,"column":26},"end":{"row":29,"column":27},"action":"remove","lines":["T"],"id":579}],[{"start":{"row":29,"column":25},"end":{"row":29,"column":26},"action":"remove","lines":["."],"id":580}],[{"start":{"row":29,"column":25},"end":{"row":29,"column":26},"action":"insert","lines":["."],"id":581}],[{"start":{"row":29,"column":26},"end":{"row":29,"column":27},"action":"insert","lines":["t"],"id":582}],[{"start":{"row":29,"column":27},"end":{"row":29,"column":28},"action":"insert","lines":["o"],"id":583}],[{"start":{"row":29,"column":28},"end":{"row":29,"column":29},"action":"insert","lines":["S"],"id":584}],[{"start":{"row":29,"column":29},"end":{"row":29,"column":30},"action":"insert","lines":["t"],"id":585}],[{"start":{"row":29,"column":30},"end":{"row":29,"column":31},"action":"insert","lines":["r"],"id":586}],[{"start":{"row":29,"column":31},"end":{"row":29,"column":32},"action":"insert","lines":["i"],"id":587}],[{"start":{"row":29,"column":32},"end":{"row":29,"column":33},"action":"insert","lines":["n"],"id":588}],[{"start":{"row":29,"column":33},"end":{"row":29,"column":34},"action":"insert","lines":["g"],"id":589}],[{"start":{"row":29,"column":34},"end":{"row":29,"column":36},"action":"insert","lines":["()"],"id":590}],[{"start":{"row":29,"column":37},"end":{"row":29,"column":38},"action":"insert","lines":[";"],"id":591}],[{"start":{"row":25,"column":13},"end":{"row":25,"column":14},"action":"insert","lines":[" "],"id":592},{"start":{"row":25,"column":15},"end":{"row":25,"column":16},"action":"insert","lines":[" "]},{"start":{"row":29,"column":0},"end":{"row":29,"column":1},"action":"remove","lines":[" "]}],[{"start":{"row":8,"column":3},"end":{"row":8,"column":14},"action":"remove","lines":[" // private"],"id":593}],[{"start":{"row":8,"column":2},"end":{"row":8,"column":3},"action":"remove","lines":[" "],"id":594}],[{"start":{"row":8,"column":1},"end":{"row":8,"column":2},"action":"remove","lines":[" "],"id":595}],[{"start":{"row":8,"column":0},"end":{"row":8,"column":1},"action":"remove","lines":[" "],"id":596}],[{"start":{"row":7,"column":28},"end":{"row":8,"column":0},"action":"remove","lines":["",""],"id":597}],[{"start":{"row":10,"column":4},"end":{"row":10,"column":52},"action":"remove","lines":["// public methods have access to private members"],"id":598}],[{"start":{"row":10,"column":0},"end":{"row":10,"column":4},"action":"remove","lines":["    "],"id":599}],[{"start":{"row":9,"column":0},"end":{"row":10,"column":0},"action":"remove","lines":["",""],"id":600}],[{"start":{"row":23,"column":0},"end":{"row":31,"column":1},"action":"remove","lines":["CipherKey.prototype.GenerateChipherKeys = function(SessionResult) {","    const hash = crypto.createHash('sha256');","    var bytes = hash.update(SessionResult).digest('utf8');","    console.log(bytes.length)","    console.log(bytes.toString())","    var newArray = bytes.slice(0, 16);","    console.log(newArray.toString());","    this.setcipherkey(newArray);","}"],"id":601}],[{"start":{"row":22,"column":0},"end":{"row":23,"column":0},"action":"remove","lines":["",""],"id":602}],[{"start":{"row":27,"column":3},"end":{"row":52,"column":38},"action":"remove","lines":[" var key1 = crypto.createHash('sha256').update(SessionResult).digest('utf8');","    console.log(key1.length)","    console.log(key1.toString())","    var newArray = key1.slice(0, 16);","    var newArray1 = key1.slice(16, 32);","    console.log(newArray.length + newArray.toString())","    console.log(\"\")","    console.log(newArray1.length + newArray1.toString())","    var iv = forge.random.getBytesSync(16);","    var cipher = forge.cipher.createCipher('AES-ECB', newArray1);","    cipher.start({","        iv: iv","    });","    cipher.update(forge.util.createBuffer(\"DDAS\"));","    cipher.finish();","    var encrypted = cipher.output;","    // outputs encrypted hex","    console.log(encrypted.toHex());","    var decipher = forge.cipher.createDecipher('AES-ECB', newArray1);","    decipher.start({","        iv: null","    });","    decipher.update(encrypted);","    decipher.finish();","    // outputs decrypted hex","    console.log(decipher.output.data);"],"id":603},{"start":{"row":27,"column":3},"end":{"row":39,"column":41},"action":"insert","lines":["// var bytesv2 = []; // char codes","    var bytes = [];","","    for (var i = 0; i < SessionResult.length; ++i) {","        var code = SessionResult.charCodeAt(i);","        bytes = bytes.concat([code]);","      //  bytesv2 = bytesv2.concat([code & 0xff, code / 256 >>> 0]);","    }","   // console.log(\"lenght is\" + bytes.length)","    var IntegrityArray = bytes.slice(Math.min(bytes.length/2,16),Math.min(bytes.length,32));","    //console.log(\"hash \" + IntegrityArray.bytes);","","    this.setintegritykey(IntegrityArray);"]}],[{"start":{"row":39,"column":4},"end":{"row":39,"column":24},"action":"remove","lines":["this.setintegritykey"],"id":604},{"start":{"row":39,"column":4},"end":{"row":39,"column":21},"action":"insert","lines":["this.setcipherkey"]}],[{"start":{"row":36,"column":37},"end":{"row":36,"column":64},"action":"remove","lines":["Math.min(bytes.length/2,16)"],"id":605},{"start":{"row":36,"column":37},"end":{"row":36,"column":38},"action":"insert","lines":["0"]}],[{"start":{"row":24,"column":30},"end":{"row":24,"column":31},"action":"insert","lines":["."],"id":608}],[{"start":{"row":24,"column":30},"end":{"row":24,"column":31},"action":"remove","lines":["."],"id":613}],[{"start":{"row":36,"column":39},"end":{"row":36,"column":64},"action":"remove","lines":["Math.min(bytes.length,32)"],"id":614},{"start":{"row":36,"column":39},"end":{"row":36,"column":66},"action":"insert","lines":["Math.min(bytes.length/2,16)"]}],[{"start":{"row":37,"column":5},"end":{"row":37,"column":6},"action":"remove","lines":["/"],"id":615}],[{"start":{"row":37,"column":4},"end":{"row":37,"column":5},"action":"remove","lines":["/"],"id":616}],[{"start":{"row":27,"column":37},"end":{"row":28,"column":0},"action":"insert","lines":["",""],"id":619},{"start":{"row":28,"column":0},"end":{"row":28,"column":3},"action":"insert","lines":["   "]}],[{"start":{"row":28,"column":3},"end":{"row":28,"column":4},"action":"insert","lines":["v"],"id":620}],[{"start":{"row":28,"column":4},"end":{"row":28,"column":5},"action":"insert","lines":["a"],"id":621}],[{"start":{"row":28,"column":5},"end":{"row":28,"column":6},"action":"insert","lines":["r"],"id":622}],[{"start":{"row":28,"column":6},"end":{"row":28,"column":7},"action":"insert","lines":[" "],"id":623}],[{"start":{"row":28,"column":7},"end":{"row":28,"column":8},"action":"insert","lines":["h"],"id":624}],[{"start":{"row":28,"column":8},"end":{"row":28,"column":9},"action":"insert","lines":["a"],"id":625}],[{"start":{"row":28,"column":9},"end":{"row":28,"column":10},"action":"insert","lines":["s"],"id":626}],[{"start":{"row":28,"column":10},"end":{"row":28,"column":11},"action":"insert","lines":["="],"id":627}],[{"start":{"row":28,"column":11},"end":{"row":28,"column":73},"action":"insert","lines":["  crypto.createHash('sha256').update('alice', 'utf8').digest()"],"id":628}],[{"start":{"row":28,"column":32},"end":{"row":28,"column":39},"action":"remove","lines":["sha256'"],"id":629},{"start":{"row":28,"column":32},"end":{"row":28,"column":33},"action":"insert","lines":["m"]}],[{"start":{"row":28,"column":33},"end":{"row":28,"column":34},"action":"insert","lines":["d"],"id":630}],[{"start":{"row":28,"column":34},"end":{"row":28,"column":35},"action":"insert","lines":["5"],"id":631}],[{"start":{"row":28,"column":35},"end":{"row":28,"column":36},"action":"insert","lines":["'"],"id":632}],[{"start":{"row":28,"column":45},"end":{"row":28,"column":52},"action":"remove","lines":["'alice'"],"id":633},{"start":{"row":28,"column":45},"end":{"row":28,"column":58},"action":"insert","lines":["SessionResult"]}],[{"start":{"row":27,"column":3},"end":{"row":27,"column":4},"action":"insert","lines":[" "],"id":634},{"start":{"row":28,"column":3},"end":{"row":28,"column":4},"action":"insert","lines":[" "]},{"start":{"row":28,"column":11},"end":{"row":28,"column":12},"action":"remove","lines":["="]},{"start":{"row":28,"column":12},"end":{"row":28,"column":13},"action":"insert","lines":["="]},{"start":{"row":34,"column":6},"end":{"row":34,"column":8},"action":"insert","lines":["  "]},{"start":{"row":36,"column":0},"end":{"row":36,"column":1},"action":"insert","lines":[" "]},{"start":{"row":37,"column":39},"end":{"row":37,"column":40},"action":"insert","lines":[" "]},{"start":{"row":37,"column":61},"end":{"row":37,"column":62},"action":"insert","lines":[" "]},{"start":{"row":37,"column":63},"end":{"row":37,"column":64},"action":"insert","lines":[" "]},{"start":{"row":37,"column":66},"end":{"row":37,"column":67},"action":"insert","lines":[" "]}],[{"start":{"row":31,"column":24},"end":{"row":31,"column":38},"action":"remove","lines":["SessionResult."],"id":635},{"start":{"row":31,"column":24},"end":{"row":31,"column":25},"action":"insert","lines":["h"]}],[{"start":{"row":31,"column":25},"end":{"row":31,"column":26},"action":"insert","lines":["a"],"id":636}],[{"start":{"row":31,"column":26},"end":{"row":31,"column":27},"action":"insert","lines":["s"],"id":637}],[{"start":{"row":31,"column":27},"end":{"row":31,"column":28},"action":"insert","lines":["h"],"id":638}],[{"start":{"row":31,"column":28},"end":{"row":31,"column":29},"action":"insert","lines":["."],"id":639}],[{"start":{"row":28,"column":11},"end":{"row":28,"column":12},"action":"insert","lines":["h"],"id":640}],[{"start":{"row":32,"column":19},"end":{"row":32,"column":32},"action":"remove","lines":["SessionResult"],"id":641},{"start":{"row":32,"column":19},"end":{"row":32,"column":20},"action":"insert","lines":["h"]}],[{"start":{"row":32,"column":20},"end":{"row":32,"column":21},"action":"insert","lines":["a"],"id":642}],[{"start":{"row":32,"column":21},"end":{"row":32,"column":22},"action":"insert","lines":["s"],"id":643}],[{"start":{"row":32,"column":22},"end":{"row":32,"column":23},"action":"insert","lines":["h"],"id":644}],[{"start":{"row":28,"column":34},"end":{"row":28,"column":37},"action":"remove","lines":["md5"],"id":645},{"start":{"row":28,"column":34},"end":{"row":28,"column":38},"action":"insert","lines":["sha1"]}],[{"start":{"row":37,"column":40},"end":{"row":37,"column":70},"action":"remove","lines":["Math.min(bytes.length / 2, 16)"],"id":646},{"start":{"row":37,"column":40},"end":{"row":37,"column":41},"action":"insert","lines":["1"]}],[{"start":{"row":37,"column":41},"end":{"row":37,"column":42},"action":"insert","lines":["6"],"id":647}],[{"start":{"row":28,"column":34},"end":{"row":28,"column":38},"action":"remove","lines":["sha1"],"id":648},{"start":{"row":28,"column":34},"end":{"row":28,"column":40},"action":"insert","lines":["sha256"]}],[{"start":{"row":28,"column":81},"end":{"row":29,"column":0},"action":"insert","lines":["",""],"id":649},{"start":{"row":29,"column":0},"end":{"row":29,"column":4},"action":"insert","lines":["    "]}],[{"start":{"row":29,"column":4},"end":{"row":29,"column":5},"action":"insert","lines":["v"],"id":650}],[{"start":{"row":29,"column":5},"end":{"row":29,"column":6},"action":"insert","lines":["a"],"id":651}],[{"start":{"row":29,"column":6},"end":{"row":29,"column":7},"action":"insert","lines":["r"],"id":652}],[{"start":{"row":29,"column":7},"end":{"row":29,"column":8},"action":"insert","lines":[" "],"id":653}],[{"start":{"row":29,"column":8},"end":{"row":29,"column":9},"action":"insert","lines":["s"],"id":654}],[{"start":{"row":29,"column":9},"end":{"row":29,"column":10},"action":"insert","lines":["t"],"id":655}],[{"start":{"row":29,"column":10},"end":{"row":29,"column":11},"action":"insert","lines":["r"],"id":656}],[{"start":{"row":29,"column":11},"end":{"row":29,"column":12},"action":"insert","lines":["i"],"id":657}],[{"start":{"row":29,"column":12},"end":{"row":29,"column":13},"action":"insert","lines":["n"],"id":658}],[{"start":{"row":29,"column":13},"end":{"row":29,"column":14},"action":"insert","lines":["="],"id":659}],[{"start":{"row":29,"column":14},"end":{"row":29,"column":15},"action":"insert","lines":["h"],"id":660}],[{"start":{"row":29,"column":15},"end":{"row":29,"column":16},"action":"insert","lines":["a"],"id":661}],[{"start":{"row":29,"column":16},"end":{"row":29,"column":17},"action":"insert","lines":["s"],"id":662}],[{"start":{"row":29,"column":17},"end":{"row":29,"column":18},"action":"insert","lines":["h"],"id":663}],[{"start":{"row":29,"column":18},"end":{"row":29,"column":19},"action":"insert","lines":["."],"id":664}],[{"start":{"row":29,"column":19},"end":{"row":29,"column":20},"action":"insert","lines":["t"],"id":665}],[{"start":{"row":29,"column":20},"end":{"row":29,"column":21},"action":"insert","lines":["o"],"id":666}],[{"start":{"row":29,"column":19},"end":{"row":29,"column":21},"action":"remove","lines":["to"],"id":667},{"start":{"row":29,"column":19},"end":{"row":29,"column":29},"action":"insert","lines":["toString()"]}],[{"start":{"row":29,"column":29},"end":{"row":29,"column":30},"action":"insert","lines":[";"],"id":668}],[{"start":{"row":32,"column":24},"end":{"row":32,"column":29},"action":"remove","lines":["hash."],"id":669},{"start":{"row":32,"column":24},"end":{"row":32,"column":29},"action":"insert","lines":["strin"]}],[{"start":{"row":32,"column":29},"end":{"row":32,"column":30},"action":"insert","lines":["."],"id":670}],[{"start":{"row":33,"column":19},"end":{"row":33,"column":23},"action":"remove","lines":["hash"],"id":671},{"start":{"row":33,"column":19},"end":{"row":33,"column":24},"action":"insert","lines":["strin"]}],[{"start":{"row":28,"column":40},"end":{"row":28,"column":41},"action":"remove","lines":["'"],"id":672}],[{"start":{"row":28,"column":39},"end":{"row":28,"column":40},"action":"remove","lines":["6"],"id":673}],[{"start":{"row":28,"column":38},"end":{"row":28,"column":39},"action":"remove","lines":["5"],"id":674}],[{"start":{"row":28,"column":37},"end":{"row":28,"column":38},"action":"remove","lines":["2"],"id":675}],[{"start":{"row":28,"column":37},"end":{"row":28,"column":38},"action":"insert","lines":["1"],"id":676}],[{"start":{"row":28,"column":38},"end":{"row":28,"column":39},"action":"insert","lines":["'"],"id":677}],[{"start":{"row":27,"column":2},"end":{"row":37,"column":46},"action":"remove","lines":["  // var bytesv2 = []; // char codes","    var hash = crypto.createHash('sha1').update(SessionResult, 'utf8').digest()","    var strin=hash.toString();","    var bytes = [];","","    for (var i = 0; i < strin.length; ++i) {","        var code = strin.charCodeAt(i);","        bytes = bytes.concat([code]);","        //  bytesv2 = bytesv2.concat([code & 0xff, code / 256 >>> 0]);","    }","    // console.log(\"lenght is\" + bytes.length)"],"id":678},{"start":{"row":27,"column":2},"end":{"row":35,"column":45},"action":"insert","lines":["// var bytesv2 = []; // char codes","    var bytes = [];","","    for (var i = 0; i < SessionResult.length; ++i) {","        var code = SessionResult.charCodeAt(i);","        bytes = bytes.concat([code]);","      //  bytesv2 = bytesv2.concat([code & 0xff, code / 256 >>> 0]);","    }","   // console.log(\"lenght is\" + bytes.length)"]}],[{"start":{"row":36,"column":40},"end":{"row":36,"column":42},"action":"remove","lines":["16"],"id":679},{"start":{"row":36,"column":40},"end":{"row":36,"column":67},"action":"insert","lines":["Math.min(bytes.length/2,16)"]}]]},"timestamp":1474893899907}