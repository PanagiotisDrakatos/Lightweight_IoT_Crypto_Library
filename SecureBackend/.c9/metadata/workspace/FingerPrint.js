{"changed":true,"filter":false,"title":"FingerPrint.js","tooltip":"/FingerPrint.js","value":"'use strict';\nconst crypto = require('crypto');\n\nexports.SignData = function(Encrypted, PrivateKey) {\n    var privateKey = PrivateKey.toString('base64');\n    var signature = crypto.createSign('RSA-SHA256');\n    signature.update(Encrypted);\n    var base64encoded = signature.sign(privateKey, 'base64');\n    return base64encoded;\n}\n\n","undoManager":{"mark":-7,"position":100,"stack":[[{"start":{"row":2,"column":1},"end":{"row":2,"column":2},"action":"insert","lines":["a"],"id":7}],[{"start":{"row":2,"column":2},"end":{"row":2,"column":3},"action":"insert","lines":["r"],"id":8}],[{"start":{"row":2,"column":3},"end":{"row":2,"column":4},"action":"insert","lines":[" "],"id":9}],[{"start":{"row":2,"column":4},"end":{"row":2,"column":5},"action":"insert","lines":["S"],"id":10}],[{"start":{"row":2,"column":5},"end":{"row":2,"column":6},"action":"insert","lines":["i"],"id":11}],[{"start":{"row":2,"column":6},"end":{"row":2,"column":7},"action":"insert","lines":["g"],"id":12}],[{"start":{"row":2,"column":7},"end":{"row":2,"column":8},"action":"insert","lines":["H"],"id":13}],[{"start":{"row":2,"column":8},"end":{"row":2,"column":9},"action":"insert","lines":["a"],"id":14}],[{"start":{"row":2,"column":9},"end":{"row":2,"column":10},"action":"insert","lines":["s"],"id":15}],[{"start":{"row":2,"column":10},"end":{"row":2,"column":11},"action":"insert","lines":["h"],"id":16}],[{"start":{"row":2,"column":11},"end":{"row":2,"column":12},"action":"insert","lines":["="],"id":17}],[{"start":{"row":2,"column":12},"end":{"row":2,"column":14},"action":"insert","lines":["''"],"id":18}],[{"start":{"row":2,"column":13},"end":{"row":2,"column":25},"action":"insert","lines":["'RSA-SHA256'"],"id":19}],[{"start":{"row":2,"column":25},"end":{"row":2,"column":26},"action":"remove","lines":["'"],"id":20}],[{"start":{"row":2,"column":12},"end":{"row":2,"column":14},"action":"remove","lines":["''"],"id":21}],[{"start":{"row":2,"column":12},"end":{"row":2,"column":13},"action":"insert","lines":["'"],"id":22}],[{"start":{"row":2,"column":23},"end":{"row":2,"column":24},"action":"remove","lines":["'"],"id":23}],[{"start":{"row":2,"column":22},"end":{"row":2,"column":23},"action":"remove","lines":["6"],"id":24}],[{"start":{"row":2,"column":21},"end":{"row":2,"column":22},"action":"remove","lines":["5"],"id":25}],[{"start":{"row":2,"column":20},"end":{"row":2,"column":21},"action":"remove","lines":["2"],"id":26}],[{"start":{"row":2,"column":19},"end":{"row":2,"column":20},"action":"remove","lines":["A"],"id":27}],[{"start":{"row":2,"column":18},"end":{"row":2,"column":19},"action":"remove","lines":["H"],"id":28}],[{"start":{"row":2,"column":17},"end":{"row":2,"column":18},"action":"remove","lines":["S"],"id":29}],[{"start":{"row":2,"column":16},"end":{"row":2,"column":17},"action":"remove","lines":["-"],"id":30}],[{"start":{"row":2,"column":15},"end":{"row":2,"column":16},"action":"remove","lines":["A"],"id":31}],[{"start":{"row":2,"column":14},"end":{"row":2,"column":15},"action":"remove","lines":["S"],"id":32}],[{"start":{"row":2,"column":13},"end":{"row":2,"column":14},"action":"remove","lines":["R"],"id":33}],[{"start":{"row":2,"column":12},"end":{"row":2,"column":13},"action":"remove","lines":["'"],"id":34}],[{"start":{"row":2,"column":11},"end":{"row":2,"column":12},"action":"remove","lines":["="],"id":35}],[{"start":{"row":2,"column":10},"end":{"row":2,"column":11},"action":"remove","lines":["h"],"id":36}],[{"start":{"row":2,"column":9},"end":{"row":2,"column":10},"action":"remove","lines":["s"],"id":37}],[{"start":{"row":2,"column":8},"end":{"row":2,"column":9},"action":"remove","lines":["a"],"id":38},{"start":{"row":2,"column":7},"end":{"row":2,"column":8},"action":"remove","lines":["H"]}],[{"start":{"row":2,"column":6},"end":{"row":2,"column":7},"action":"remove","lines":["g"],"id":39},{"start":{"row":2,"column":5},"end":{"row":2,"column":6},"action":"remove","lines":["i"]}],[{"start":{"row":2,"column":4},"end":{"row":2,"column":5},"action":"remove","lines":["S"],"id":40}],[{"start":{"row":2,"column":3},"end":{"row":2,"column":4},"action":"remove","lines":[" "],"id":41}],[{"start":{"row":2,"column":2},"end":{"row":2,"column":3},"action":"remove","lines":["r"],"id":42}],[{"start":{"row":2,"column":1},"end":{"row":2,"column":2},"action":"remove","lines":["a"],"id":43}],[{"start":{"row":2,"column":0},"end":{"row":2,"column":1},"action":"remove","lines":["v"],"id":44}],[{"start":{"row":1,"column":33},"end":{"row":2,"column":0},"action":"remove","lines":["",""],"id":45}],[{"start":{"row":1,"column":33},"end":{"row":2,"column":0},"action":"insert","lines":["",""],"id":46}],[{"start":{"row":8,"column":21},"end":{"row":8,"column":41},"action":"remove","lines":["privateKey.sign(md);"],"id":47},{"start":{"row":8,"column":21},"end":{"row":8,"column":53},"action":"insert","lines":["crypto.createSign('RSA-SHA256');"]}],[{"start":{"row":8,"column":53},"end":{"row":9,"column":0},"action":"insert","lines":["",""],"id":48},{"start":{"row":9,"column":0},"end":{"row":9,"column":4},"action":"insert","lines":["    "]}],[{"start":{"row":9,"column":4},"end":{"row":9,"column":26},"action":"insert","lines":["sign.update('abcdef');"],"id":49}],[{"start":{"row":9,"column":4},"end":{"row":9,"column":8},"action":"remove","lines":["sign"],"id":50},{"start":{"row":9,"column":4},"end":{"row":9,"column":14},"action":"insert","lines":["_signature"]}],[{"start":{"row":4,"column":4},"end":{"row":6,"column":40},"action":"remove","lines":["var InputEncoding = 'utf8'","    var md = forge.md.sha1.create();","    md.update(Encrypted, InputEncoding);"],"id":51}],[{"start":{"row":4,"column":0},"end":{"row":4,"column":4},"action":"remove","lines":["    "],"id":52}],[{"start":{"row":3,"column":52},"end":{"row":4,"column":0},"action":"remove","lines":["",""],"id":53}],[{"start":{"row":7,"column":8},"end":{"row":7,"column":21},"action":"remove","lines":["base64encoded"],"id":54},{"start":{"row":7,"column":8},"end":{"row":7,"column":9},"action":"insert","lines":["s"]}],[{"start":{"row":7,"column":9},"end":{"row":7,"column":10},"action":"insert","lines":["i"],"id":55}],[{"start":{"row":7,"column":10},"end":{"row":7,"column":11},"action":"insert","lines":["g"],"id":56}],[{"start":{"row":7,"column":11},"end":{"row":7,"column":12},"action":"insert","lines":["n"],"id":57}],[{"start":{"row":7,"column":12},"end":{"row":7,"column":13},"action":"insert","lines":["a"],"id":58}],[{"start":{"row":7,"column":13},"end":{"row":7,"column":14},"action":"insert","lines":["t"],"id":59}],[{"start":{"row":7,"column":14},"end":{"row":7,"column":15},"action":"insert","lines":["u"],"id":60}],[{"start":{"row":7,"column":15},"end":{"row":7,"column":16},"action":"insert","lines":["r"],"id":61}],[{"start":{"row":7,"column":16},"end":{"row":7,"column":17},"action":"insert","lines":["e"],"id":62}],[{"start":{"row":7,"column":8},"end":{"row":7,"column":17},"action":"remove","lines":["signature"],"id":63},{"start":{"row":7,"column":8},"end":{"row":7,"column":21},"action":"insert","lines":["base64encoded"]}],[{"start":{"row":7,"column":24},"end":{"row":7,"column":56},"action":"remove","lines":["forge.util.encode64(_signature);"],"id":64},{"start":{"row":7,"column":24},"end":{"row":7,"column":46},"action":"insert","lines":["sign.sign(key, 'hex');"]}],[{"start":{"row":5,"column":8},"end":{"row":5,"column":9},"action":"remove","lines":["_"],"id":65}],[{"start":{"row":6,"column":5},"end":{"row":6,"column":6},"action":"remove","lines":["s"],"id":66}],[{"start":{"row":6,"column":4},"end":{"row":6,"column":5},"action":"remove","lines":["_"],"id":67}],[{"start":{"row":6,"column":4},"end":{"row":6,"column":5},"action":"insert","lines":["s"],"id":68}],[{"start":{"row":7,"column":24},"end":{"row":7,"column":28},"action":"remove","lines":["sign"],"id":69},{"start":{"row":7,"column":24},"end":{"row":7,"column":33},"action":"insert","lines":["signature"]}],[{"start":{"row":7,"column":47},"end":{"row":7,"column":48},"action":"remove","lines":["x"],"id":70}],[{"start":{"row":7,"column":46},"end":{"row":7,"column":47},"action":"remove","lines":["e"],"id":71}],[{"start":{"row":7,"column":45},"end":{"row":7,"column":46},"action":"remove","lines":["h"],"id":72}],[{"start":{"row":7,"column":45},"end":{"row":7,"column":46},"action":"insert","lines":["b"],"id":73}],[{"start":{"row":7,"column":46},"end":{"row":7,"column":47},"action":"insert","lines":["a"],"id":74}],[{"start":{"row":7,"column":47},"end":{"row":7,"column":48},"action":"insert","lines":["s"],"id":75}],[{"start":{"row":7,"column":48},"end":{"row":7,"column":49},"action":"insert","lines":["e"],"id":76}],[{"start":{"row":7,"column":49},"end":{"row":7,"column":50},"action":"insert","lines":["6"],"id":77}],[{"start":{"row":7,"column":50},"end":{"row":7,"column":51},"action":"insert","lines":["4"],"id":78}],[{"start":{"row":7,"column":39},"end":{"row":7,"column":40},"action":"insert","lines":["p"],"id":79}],[{"start":{"row":7,"column":40},"end":{"row":7,"column":41},"action":"insert","lines":["r"],"id":80}],[{"start":{"row":7,"column":41},"end":{"row":7,"column":42},"action":"insert","lines":["i"],"id":81}],[{"start":{"row":7,"column":42},"end":{"row":7,"column":43},"action":"insert","lines":["v"],"id":82}],[{"start":{"row":7,"column":43},"end":{"row":7,"column":44},"action":"insert","lines":["a"],"id":83}],[{"start":{"row":7,"column":44},"end":{"row":7,"column":45},"action":"insert","lines":["t"],"id":84}],[{"start":{"row":7,"column":45},"end":{"row":7,"column":46},"action":"insert","lines":["e"],"id":85}],[{"start":{"row":7,"column":46},"end":{"row":7,"column":47},"action":"remove","lines":["k"],"id":86}],[{"start":{"row":7,"column":46},"end":{"row":7,"column":47},"action":"insert","lines":["K"],"id":87}],[{"start":{"row":4,"column":46},"end":{"row":4,"column":47},"action":"remove","lines":["i"],"id":88}],[{"start":{"row":4,"column":45},"end":{"row":4,"column":46},"action":"remove","lines":["i"],"id":89}],[{"start":{"row":4,"column":44},"end":{"row":4,"column":45},"action":"remove","lines":["c"],"id":90}],[{"start":{"row":4,"column":43},"end":{"row":4,"column":44},"action":"remove","lines":["s"],"id":91}],[{"start":{"row":4,"column":42},"end":{"row":4,"column":43},"action":"remove","lines":["a"],"id":92}],[{"start":{"row":4,"column":42},"end":{"row":4,"column":43},"action":"insert","lines":["b"],"id":93}],[{"start":{"row":4,"column":43},"end":{"row":4,"column":44},"action":"insert","lines":["a"],"id":94}],[{"start":{"row":4,"column":44},"end":{"row":4,"column":45},"action":"insert","lines":["s"],"id":95}],[{"start":{"row":4,"column":45},"end":{"row":4,"column":46},"action":"insert","lines":["e"],"id":96}],[{"start":{"row":4,"column":46},"end":{"row":4,"column":47},"action":"insert","lines":["6"],"id":97}],[{"start":{"row":4,"column":47},"end":{"row":4,"column":48},"action":"insert","lines":["4"],"id":98}],[{"start":{"row":6,"column":28},"end":{"row":6,"column":29},"action":"remove","lines":["'"],"id":99}],[{"start":{"row":6,"column":27},"end":{"row":6,"column":28},"action":"remove","lines":["f"],"id":100}],[{"start":{"row":6,"column":26},"end":{"row":6,"column":27},"action":"remove","lines":["e"],"id":101}],[{"start":{"row":6,"column":25},"end":{"row":6,"column":26},"action":"remove","lines":["d"],"id":102}],[{"start":{"row":6,"column":24},"end":{"row":6,"column":25},"action":"remove","lines":["c"],"id":103}],[{"start":{"row":6,"column":23},"end":{"row":6,"column":24},"action":"remove","lines":["b"],"id":104}],[{"start":{"row":6,"column":22},"end":{"row":6,"column":23},"action":"remove","lines":["a"],"id":105}],[{"start":{"row":6,"column":21},"end":{"row":6,"column":22},"action":"remove","lines":["'"],"id":106}],[{"start":{"row":6,"column":21},"end":{"row":6,"column":30},"action":"insert","lines":["Encrypted"],"id":107}]]},"ace":{"folds":[],"scrolltop":0,"scrollleft":0,"selection":{"start":{"row":6,"column":32},"end":{"row":6,"column":32},"isBackwards":false},"options":{"guessTabSize":true,"useWrapMode":false,"wrapToView":true},"firstLineState":{"row":7,"state":"start","mode":"ace/mode/javascript"}},"timestamp":1476540772831}