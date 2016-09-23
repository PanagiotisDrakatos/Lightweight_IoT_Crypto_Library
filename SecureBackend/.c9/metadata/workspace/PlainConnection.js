{"changed":true,"filter":false,"title":"PlainConnection.js","tooltip":"/PlainConnection.js","value":"'use strict';\n\n//npm install -g node-gyp\n//npm install ursa\n\n//npm install bluebird\n//npm install mkdirp@latest\n\n//npm install node-forge\n//npm install big-integer\n\n//npm install mongodb\n\nvar _HOST = '192.168.1.66';\nvar _PORT = 1337;\nvar _address;\n\nvar net = require('net');\nvar userCount = 0;\nconst BasicProtocolEmmitter = require(\"./IOTransports\");\nvar ProtocolEmmitter = new BasicProtocolEmmitter();\n\nvar server = net.createServer(function(socket) {\n    socket.on('connect', (e) => {\n        console.log('client connected ' +\n            socket.remoteAddress + ':' +\n            socket.remotePort);\n    });\n\n    socket.on('data', function(data) {\n        //console.log('clients says' + ': ' + data);\n        userCount++;\n        ProtocolEmmitter.Receive(data);\n        // socket.pipe(socket);\n        if (userCount != 2) {\n            var send = ProtocolEmmitter.send();\n        ///    console.log('Server says' + ': ' + send);\n            socket.write(send + '\\n');\n        }\n\n    });\n\n    socket.on('error', function(data) {\n        console.log('client on error', data);\n\n    });\n\n    socket.on('close', (e) => {\n        console.log('client disconnected');\n        socket.end;\n        ProtocolEmmitter = new BasicProtocolEmmitter();\n        userCount = 0;\n    });\n\n});\nserver.on('Error', (e) => {\n    if (e.code == 'EADDRINUSE') {\n        console.log('Address alredy bind  retrying...');\n        setTimeout(() => {\n            server.close();\n            server.listen(_PORT, _HOST);\n        }, 10000);\n    }\n});\n\nserver.listen(_PORT, _HOST, () => {\n    _address = server.address();\n    console.log('opened server on %j', _address);\n    console.log(' Server listening on %j ', _HOST, ':', _PORT);\n});","undoManager":{"mark":101,"position":100,"stack":[[{"start":{"row":32,"column":9},"end":{"row":32,"column":10},"action":"remove","lines":["s"],"id":76}],[{"start":{"row":32,"column":8},"end":{"row":32,"column":9},"action":"remove","lines":["u"],"id":77}],[{"start":{"row":22,"column":4},"end":{"row":22,"column":26},"action":"remove","lines":["const ProtocolEmmitter"],"id":78}],[{"start":{"row":19,"column":56},"end":{"row":20,"column":0},"action":"insert","lines":["",""],"id":79}],[{"start":{"row":20,"column":0},"end":{"row":20,"column":22},"action":"insert","lines":["const ProtocolEmmitter"],"id":80}],[{"start":{"row":20,"column":22},"end":{"row":20,"column":23},"action":"insert","lines":[";"],"id":81}],[{"start":{"row":23,"column":4},"end":{"row":23,"column":26},"action":"insert","lines":["const ProtocolEmmitter"],"id":82}],[{"start":{"row":23,"column":4},"end":{"row":23,"column":10},"action":"remove","lines":["const "],"id":83}],[{"start":{"row":23,"column":51},"end":{"row":24,"column":0},"action":"remove","lines":["",""],"id":84}],[{"start":{"row":66,"column":27},"end":{"row":67,"column":0},"action":"insert","lines":["",""],"id":85},{"start":{"row":67,"column":0},"end":{"row":67,"column":12},"action":"insert","lines":["            "]}],[{"start":{"row":67,"column":12},"end":{"row":67,"column":60},"action":"insert","lines":[" ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":86}],[{"start":{"row":40,"column":0},"end":{"row":40,"column":5},"action":"remove","lines":["     "],"id":87},{"start":{"row":67,"column":0},"end":{"row":67,"column":1},"action":"remove","lines":[" "]}],[{"start":{"row":20,"column":22},"end":{"row":20,"column":23},"action":"insert","lines":["="],"id":88}],[{"start":{"row":20,"column":23},"end":{"row":20,"column":24},"action":"insert","lines":["n"],"id":89}],[{"start":{"row":20,"column":24},"end":{"row":20,"column":25},"action":"insert","lines":["u"],"id":90}],[{"start":{"row":20,"column":25},"end":{"row":20,"column":26},"action":"insert","lines":["l"],"id":91}],[{"start":{"row":20,"column":26},"end":{"row":20,"column":27},"action":"insert","lines":["l"],"id":92}],[{"start":{"row":20,"column":26},"end":{"row":20,"column":27},"action":"remove","lines":["l"],"id":93}],[{"start":{"row":20,"column":25},"end":{"row":20,"column":26},"action":"remove","lines":["l"],"id":94}],[{"start":{"row":20,"column":24},"end":{"row":20,"column":25},"action":"remove","lines":["u"],"id":95}],[{"start":{"row":20,"column":23},"end":{"row":20,"column":24},"action":"remove","lines":["n"],"id":96}],[{"start":{"row":20,"column":23},"end":{"row":20,"column":25},"action":"insert","lines":["''"],"id":97}],[{"start":{"row":20,"column":0},"end":{"row":20,"column":6},"action":"remove","lines":["const "],"id":98},{"start":{"row":20,"column":0},"end":{"row":20,"column":1},"action":"insert","lines":["v"]}],[{"start":{"row":20,"column":1},"end":{"row":20,"column":2},"action":"insert","lines":["a"],"id":99}],[{"start":{"row":20,"column":2},"end":{"row":20,"column":3},"action":"insert","lines":["r"],"id":100}],[{"start":{"row":20,"column":3},"end":{"row":20,"column":4},"action":"insert","lines":[" "],"id":101}],[{"start":{"row":35,"column":29},"end":{"row":36,"column":0},"action":"insert","lines":["",""],"id":102},{"start":{"row":36,"column":0},"end":{"row":36,"column":12},"action":"insert","lines":["            "]}],[{"start":{"row":36,"column":12},"end":{"row":36,"column":26},"action":"insert","lines":["userCount = 0;"],"id":103}],[{"start":{"row":36,"column":11},"end":{"row":36,"column":26},"action":"remove","lines":[" userCount = 0;"],"id":104}],[{"start":{"row":36,"column":10},"end":{"row":36,"column":11},"action":"remove","lines":[" "],"id":105}],[{"start":{"row":36,"column":9},"end":{"row":36,"column":10},"action":"remove","lines":[" "],"id":106}],[{"start":{"row":36,"column":8},"end":{"row":36,"column":9},"action":"remove","lines":[" "],"id":107}],[{"start":{"row":36,"column":4},"end":{"row":36,"column":8},"action":"remove","lines":["    "],"id":108}],[{"start":{"row":36,"column":0},"end":{"row":36,"column":4},"action":"remove","lines":["    "],"id":109}],[{"start":{"row":35,"column":29},"end":{"row":36,"column":0},"action":"remove","lines":["",""],"id":110}],[{"start":{"row":39,"column":9},"end":{"row":40,"column":0},"action":"insert","lines":["",""],"id":111},{"start":{"row":40,"column":0},"end":{"row":40,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":40,"column":8},"end":{"row":40,"column":9},"action":"insert","lines":["e"],"id":112}],[{"start":{"row":40,"column":9},"end":{"row":40,"column":10},"action":"insert","lines":["l"],"id":113}],[{"start":{"row":40,"column":10},"end":{"row":40,"column":11},"action":"insert","lines":["s"],"id":114}],[{"start":{"row":40,"column":11},"end":{"row":40,"column":12},"action":"insert","lines":["e"],"id":115}],[{"start":{"row":40,"column":12},"end":{"row":41,"column":0},"action":"insert","lines":["",""],"id":116},{"start":{"row":41,"column":0},"end":{"row":41,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":41,"column":8},"end":{"row":41,"column":9},"action":"insert","lines":[" "],"id":117}],[{"start":{"row":41,"column":9},"end":{"row":41,"column":24},"action":"insert","lines":[" userCount = 0;"],"id":118}],[{"start":{"row":20,"column":20},"end":{"row":20,"column":21},"action":"insert","lines":[" "],"id":119},{"start":{"row":20,"column":22},"end":{"row":20,"column":23},"action":"insert","lines":[" "]},{"start":{"row":41,"column":0},"end":{"row":41,"column":2},"action":"insert","lines":["  "]}],[{"start":{"row":69,"column":11},"end":{"row":69,"column":59},"action":"remove","lines":[" ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":120}],[{"start":{"row":69,"column":10},"end":{"row":69,"column":11},"action":"remove","lines":[" "],"id":121}],[{"start":{"row":69,"column":9},"end":{"row":69,"column":10},"action":"remove","lines":[" "],"id":122}],[{"start":{"row":69,"column":8},"end":{"row":69,"column":9},"action":"remove","lines":[" "],"id":123}],[{"start":{"row":69,"column":4},"end":{"row":69,"column":8},"action":"remove","lines":["    "],"id":124}],[{"start":{"row":69,"column":0},"end":{"row":69,"column":4},"action":"remove","lines":["    "],"id":125}],[{"start":{"row":68,"column":27},"end":{"row":69,"column":0},"action":"remove","lines":["",""],"id":126}],[{"start":{"row":40,"column":7},"end":{"row":41,"column":26},"action":"remove","lines":[" else","            userCount = 0;"],"id":127}],[{"start":{"row":40,"column":6},"end":{"row":40,"column":7},"action":"remove","lines":[" "],"id":128}],[{"start":{"row":40,"column":5},"end":{"row":40,"column":6},"action":"remove","lines":[" "],"id":129}],[{"start":{"row":40,"column":4},"end":{"row":40,"column":5},"action":"remove","lines":[" "],"id":130}],[{"start":{"row":40,"column":0},"end":{"row":40,"column":4},"action":"remove","lines":["    "],"id":131}],[{"start":{"row":39,"column":9},"end":{"row":40,"column":0},"action":"remove","lines":["",""],"id":132}],[{"start":{"row":64,"column":56},"end":{"row":65,"column":0},"action":"insert","lines":["",""],"id":133},{"start":{"row":65,"column":0},"end":{"row":65,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":65,"column":8},"end":{"row":65,"column":22},"action":"insert","lines":["userCount = 0;"],"id":134}],[{"start":{"row":65,"column":22},"end":{"row":66,"column":0},"action":"insert","lines":["",""],"id":135},{"start":{"row":66,"column":0},"end":{"row":66,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":66,"column":8},"end":{"row":66,"column":55},"action":"insert","lines":["ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":136}],[{"start":{"row":23,"column":4},"end":{"row":23,"column":51},"action":"remove","lines":["ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":137}],[{"start":{"row":23,"column":0},"end":{"row":23,"column":4},"action":"remove","lines":["    "],"id":138}],[{"start":{"row":22,"column":48},"end":{"row":23,"column":0},"action":"remove","lines":["",""],"id":139}],[{"start":{"row":23,"column":33},"end":{"row":24,"column":0},"action":"insert","lines":["",""],"id":140},{"start":{"row":24,"column":0},"end":{"row":24,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":24,"column":8},"end":{"row":24,"column":55},"action":"insert","lines":["ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":141}],[{"start":{"row":24,"column":55},"end":{"row":25,"column":0},"action":"insert","lines":["",""],"id":142},{"start":{"row":25,"column":0},"end":{"row":25,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":25,"column":8},"end":{"row":25,"column":22},"action":"insert","lines":["userCount = 0;"],"id":143}],[{"start":{"row":66,"column":8},"end":{"row":67,"column":55},"action":"remove","lines":["userCount = 0;","        ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":144}],[{"start":{"row":66,"column":4},"end":{"row":66,"column":8},"action":"remove","lines":["    "],"id":145}],[{"start":{"row":66,"column":0},"end":{"row":66,"column":4},"action":"remove","lines":["    "],"id":146}],[{"start":{"row":65,"column":56},"end":{"row":66,"column":0},"action":"remove","lines":["",""],"id":147}],[{"start":{"row":24,"column":8},"end":{"row":25,"column":22},"action":"remove","lines":["ProtocolEmmitter = new BasicProtocolEmmitter();","        userCount = 0;"],"id":148}],[{"start":{"row":24,"column":4},"end":{"row":24,"column":8},"action":"remove","lines":["    "],"id":149}],[{"start":{"row":24,"column":0},"end":{"row":24,"column":4},"action":"remove","lines":["    "],"id":150}],[{"start":{"row":23,"column":33},"end":{"row":24,"column":0},"action":"remove","lines":["",""],"id":151}],[{"start":{"row":50,"column":4},"end":{"row":57,"column":18},"action":"remove","lines":["    setTimeout(() => {","            server.close();","            server.listen(_PORT, _HOST, () => {","                _address = server.address();","                console.log('opened server on %j', _address);","                console.log(' Server listening on %j ', _HOST, ':', _PORT);","            });","        }, 10000);"],"id":292}],[{"start":{"row":50,"column":0},"end":{"row":50,"column":4},"action":"remove","lines":["    "],"id":293}],[{"start":{"row":49,"column":19},"end":{"row":50,"column":0},"action":"remove","lines":["",""],"id":294}],[{"start":{"row":20,"column":23},"end":{"row":20,"column":26},"action":"remove","lines":["'';"],"id":295},{"start":{"row":20,"column":23},"end":{"row":20,"column":24},"action":"insert","lines":["n"]}],[{"start":{"row":20,"column":24},"end":{"row":20,"column":25},"action":"insert","lines":["e"],"id":296}],[{"start":{"row":20,"column":25},"end":{"row":20,"column":26},"action":"insert","lines":["w"],"id":297}],[{"start":{"row":20,"column":26},"end":{"row":20,"column":27},"action":"insert","lines":[" "],"id":298}],[{"start":{"row":20,"column":27},"end":{"row":20,"column":28},"action":"insert","lines":["B"],"id":299}],[{"start":{"row":20,"column":27},"end":{"row":20,"column":28},"action":"remove","lines":["B"],"id":300},{"start":{"row":20,"column":27},"end":{"row":20,"column":50},"action":"insert","lines":["BasicProtocolEmmitter()"]}],[{"start":{"row":20,"column":50},"end":{"row":20,"column":51},"action":"insert","lines":[";"],"id":301}],[{"start":{"row":49,"column":19},"end":{"row":50,"column":0},"action":"insert","lines":["",""],"id":302},{"start":{"row":50,"column":0},"end":{"row":50,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":50,"column":8},"end":{"row":50,"column":55},"action":"insert","lines":["ProtocolEmmitter = new BasicProtocolEmmitter();"],"id":303}],[{"start":{"row":50,"column":55},"end":{"row":51,"column":0},"action":"insert","lines":["",""],"id":304},{"start":{"row":51,"column":0},"end":{"row":51,"column":8},"action":"insert","lines":["        "]}],[{"start":{"row":51,"column":8},"end":{"row":51,"column":22},"action":"insert","lines":["userCount = 0;"],"id":305}],[{"start":{"row":49,"column":7},"end":{"row":49,"column":19},"action":"remove","lines":[" socket.end;"],"id":306}],[{"start":{"row":49,"column":6},"end":{"row":49,"column":7},"action":"remove","lines":[" "],"id":307}],[{"start":{"row":49,"column":5},"end":{"row":49,"column":6},"action":"remove","lines":[" "],"id":308}],[{"start":{"row":49,"column":4},"end":{"row":49,"column":5},"action":"remove","lines":[" "],"id":309}],[{"start":{"row":49,"column":4},"end":{"row":49,"column":16},"action":"insert","lines":[" socket.end;"],"id":310}],[{"start":{"row":49,"column":5},"end":{"row":49,"column":8},"action":"insert","lines":["   "],"id":311}],[{"start":{"row":30,"column":8},"end":{"row":30,"column":9},"action":"insert","lines":["/"],"id":312}],[{"start":{"row":30,"column":9},"end":{"row":30,"column":10},"action":"insert","lines":["/"],"id":313}],[{"start":{"row":36,"column":8},"end":{"row":36,"column":9},"action":"insert","lines":["/"],"id":314}],[{"start":{"row":36,"column":9},"end":{"row":36,"column":10},"action":"insert","lines":["/"],"id":336}],[{"start":{"row":36,"column":10},"end":{"row":36,"column":11},"action":"insert","lines":["/"],"id":350}],[{"start":{"row":15,"column":0},"end":{"row":15,"column":3},"action":"remove","lines":["   "],"id":350}],[{"start":{"row":12,"column":32},"end":{"row":12,"column":33},"action":"insert","lines":[";"],"id":351}],[{"start":{"row":12,"column":32},"end":{"row":12,"column":33},"action":"remove","lines":[","],"id":352}],[{"start":{"row":12,"column":33},"end":{"row":13,"column":0},"action":"remove","lines":["",""],"id":353}],[{"start":{"row":13,"column":0},"end":{"row":13,"column":4},"action":"remove","lines":["    "],"id":354}],[{"start":{"row":13,"column":4},"end":{"row":15,"column":29},"action":"remove","lines":["_portSocket = 8080,","    _portRedis = 6379,","    _HostRedis = 'localhost';"],"id":355}],[{"start":{"row":18,"column":3},"end":{"row":19,"column":0},"action":"remove","lines":["",""],"id":356}],[{"start":{"row":18,"column":3},"end":{"row":24,"column":8},"action":"remove","lines":[" var server = require('http').createServer(),","        socketIO = require('socket.io').listen(server),","        redis = require('socket.io-redis');","    socketIO.adapter(redis({","        host: _HostRedis,","        port: _portRedis","    }));"],"id":357}],[{"start":{"row":12,"column":12},"end":{"row":12,"column":13},"action":"remove","lines":[" "],"id":358},{"start":{"row":12,"column":33},"end":{"row":13,"column":3},"action":"insert","lines":["","   "]},{"start":{"row":13,"column":16},"end":{"row":13,"column":17},"action":"remove","lines":[" "]},{"start":{"row":13,"column":23},"end":{"row":14,"column":3},"action":"insert","lines":["","   "]},{"start":{"row":14,"column":15},"end":{"row":14,"column":17},"action":"remove","lines":["  "]},{"start":{"row":14,"column":22},"end":{"row":15,"column":3},"action":"insert","lines":["","   "]},{"start":{"row":15,"column":14},"end":{"row":15,"column":16},"action":"remove","lines":["  "]},{"start":{"row":17,"column":23},"end":{"row":17,"column":24},"action":"remove","lines":["\t"]},{"start":{"row":18,"column":0},"end":{"row":18,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":18,"column":0},"end":{"row":18,"column":4},"action":"insert","lines":["    "]},{"start":{"row":18,"column":48},"end":{"row":19,"column":7},"action":"insert","lines":["","       "]},{"start":{"row":19,"column":55},"end":{"row":20,"column":7},"action":"insert","lines":["","       "]},{"start":{"row":20,"column":43},"end":{"row":20,"column":44},"action":"remove","lines":["\t"]},{"start":{"row":21,"column":0},"end":{"row":21,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":21,"column":0},"end":{"row":21,"column":4},"action":"insert","lines":["    "]},{"start":{"row":21,"column":28},"end":{"row":22,"column":7},"action":"insert","lines":["","       "]},{"start":{"row":22,"column":25},"end":{"row":23,"column":7},"action":"insert","lines":["","       "]},{"start":{"row":23,"column":24},"end":{"row":24,"column":3},"action":"insert","lines":["","   "]},{"start":{"row":25,"column":0},"end":{"row":25,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":26,"column":0},"end":{"row":26,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":26,"column":0},"end":{"row":26,"column":4},"action":"insert","lines":["    "]},{"start":{"row":27,"column":0},"end":{"row":27,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":27,"column":0},"end":{"row":27,"column":4},"action":"insert","lines":["    "]},{"start":{"row":28,"column":0},"end":{"row":28,"column":2},"action":"remove","lines":["\t\t"]},{"start":{"row":28,"column":0},"end":{"row":28,"column":8},"action":"insert","lines":["        "]},{"start":{"row":28,"column":23},"end":{"row":28,"column":25},"action":"remove","lines":["\t\t"]},{"start":{"row":29,"column":0},"end":{"row":29,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":29,"column":0},"end":{"row":29,"column":4},"action":"insert","lines":["    "]},{"start":{"row":30,"column":0},"end":{"row":30,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":31,"column":0},"end":{"row":31,"column":1},"action":"remove","lines":["\t"]},{"start":{"row":31,"column":0},"end":{"row":31,"column":4},"action":"insert","lines":["    "]},{"start":{"row":35,"column":8},"end":{"row":35,"column":9},"action":"remove","lines":[" "]},{"start":{"row":52,"column":23},"end":{"row":52,"column":24},"action":"remove","lines":["\t"]},{"start":{"row":53,"column":0},"end":{"row":53,"column":4},"action":"insert","lines":["    "]},{"start":{"row":54,"column":0},"end":{"row":54,"column":4},"action":"insert","lines":["    "]},{"start":{"row":55,"column":0},"end":{"row":55,"column":4},"action":"insert","lines":["    "]},{"start":{"row":57,"column":0},"end":{"row":57,"column":4},"action":"insert","lines":["    "]},{"start":{"row":58,"column":0},"end":{"row":58,"column":4},"action":"insert","lines":["    "]},{"start":{"row":59,"column":0},"end":{"row":59,"column":4},"action":"insert","lines":["    "]},{"start":{"row":60,"column":0},"end":{"row":60,"column":4},"action":"insert","lines":["    "]},{"start":{"row":62,"column":0},"end":{"row":62,"column":4},"action":"insert","lines":["    "]},{"start":{"row":63,"column":4},"end":{"row":63,"column":8},"action":"insert","lines":["    "]},{"start":{"row":64,"column":0},"end":{"row":64,"column":1},"action":"insert","lines":[" "]},{"start":{"row":64,"column":9},"end":{"row":64,"column":12},"action":"insert","lines":["   "]},{"start":{"row":65,"column":0},"end":{"row":65,"column":3},"action":"insert","lines":["   "]},{"start":{"row":65,"column":15},"end":{"row":65,"column":16},"action":"insert","lines":[" "]},{"start":{"row":66,"column":12},"end":{"row":66,"column":16},"action":"insert","lines":["    "]},{"start":{"row":67,"column":0},"end":{"row":67,"column":1},"action":"insert","lines":[" "]},{"start":{"row":67,"column":5},"end":{"row":67,"column":8},"action":"insert","lines":["   "]},{"start":{"row":69,"column":0},"end":{"row":69,"column":4},"action":"insert","lines":["    "]},{"start":{"row":70,"column":8},"end":{"row":70,"column":12},"action":"insert","lines":["    "]},{"start":{"row":71,"column":0},"end":{"row":71,"column":2},"action":"insert","lines":["  "]},{"start":{"row":71,"column":10},"end":{"row":71,"column":12},"action":"insert","lines":["  "]},{"start":{"row":72,"column":0},"end":{"row":72,"column":4},"action":"insert","lines":["    "]},{"start":{"row":73,"column":8},"end":{"row":73,"column":12},"action":"insert","lines":["    "]},{"start":{"row":74,"column":0},"end":{"row":74,"column":2},"action":"insert","lines":["  "]},{"start":{"row":74,"column":10},"end":{"row":74,"column":12},"action":"insert","lines":["  "]},{"start":{"row":75,"column":0},"end":{"row":75,"column":4},"action":"insert","lines":["    "]},{"start":{"row":76,"column":0},"end":{"row":76,"column":6},"action":"insert","lines":["      "]},{"start":{"row":76,"column":14},"end":{"row":76,"column":16},"action":"insert","lines":["  "]},{"start":{"row":77,"column":12},"end":{"row":77,"column":16},"action":"insert","lines":["    "]},{"start":{"row":78,"column":8},"end":{"row":78,"column":12},"action":"insert","lines":["    "]},{"start":{"row":80,"column":0},"end":{"row":80,"column":2},"action":"insert","lines":["  "]},{"start":{"row":80,"column":6},"end":{"row":80,"column":8},"action":"insert","lines":["  "]},{"start":{"row":82,"column":0},"end":{"row":82,"column":4},"action":"insert","lines":["    "]},{"start":{"row":83,"column":0},"end":{"row":83,"column":1},"action":"insert","lines":[" "]},{"start":{"row":83,"column":9},"end":{"row":83,"column":12},"action":"insert","lines":["   "]},{"start":{"row":85,"column":0},"end":{"row":85,"column":3},"action":"insert","lines":["   "]},{"start":{"row":85,"column":7},"end":{"row":85,"column":8},"action":"insert","lines":[" "]},{"start":{"row":87,"column":0},"end":{"row":87,"column":4},"action":"insert","lines":["    "]},{"start":{"row":88,"column":0},"end":{"row":88,"column":1},"action":"insert","lines":[" "]},{"start":{"row":88,"column":9},"end":{"row":88,"column":12},"action":"insert","lines":["   "]},{"start":{"row":89,"column":0},"end":{"row":89,"column":3},"action":"insert","lines":["   "]},{"start":{"row":89,"column":11},"end":{"row":89,"column":12},"action":"insert","lines":[" "]},{"start":{"row":90,"column":0},"end":{"row":90,"column":4},"action":"insert","lines":["    "]},{"start":{"row":91,"column":8},"end":{"row":91,"column":12},"action":"insert","lines":["    "]},{"start":{"row":92,"column":0},"end":{"row":92,"column":3},"action":"insert","lines":["   "]},{"start":{"row":92,"column":7},"end":{"row":92,"column":8},"action":"insert","lines":[" "]},{"start":{"row":94,"column":0},"end":{"row":94,"column":4},"action":"insert","lines":["    "]},{"start":{"row":95,"column":0},"end":{"row":95,"column":4},"action":"insert","lines":["    "]},{"start":{"row":96,"column":0},"end":{"row":96,"column":3},"action":"insert","lines":["   "]},{"start":{"row":96,"column":7},"end":{"row":96,"column":8},"action":"insert","lines":[" "]},{"start":{"row":97,"column":0},"end":{"row":97,"column":4},"action":"insert","lines":["    "]},{"start":{"row":98,"column":8},"end":{"row":98,"column":12},"action":"insert","lines":["    "]},{"start":{"row":99,"column":0},"end":{"row":99,"column":4},"action":"insert","lines":["    "]},{"start":{"row":100,"column":12},"end":{"row":100,"column":16},"action":"insert","lines":["    "]},{"start":{"row":101,"column":8},"end":{"row":101,"column":12},"action":"insert","lines":["    "]},{"start":{"row":102,"column":0},"end":{"row":102,"column":4},"action":"insert","lines":["    "]},{"start":{"row":103,"column":0},"end":{"row":103,"column":4},"action":"insert","lines":["    "]},{"start":{"row":105,"column":0},"end":{"row":105,"column":4},"action":"insert","lines":["    "]},{"start":{"row":106,"column":0},"end":{"row":106,"column":4},"action":"insert","lines":["    "]},{"start":{"row":107,"column":4},"end":{"row":107,"column":8},"action":"insert","lines":["    "]},{"start":{"row":108,"column":0},"end":{"row":108,"column":4},"action":"insert","lines":["    "]},{"start":{"row":109,"column":0},"end":{"row":109,"column":4},"action":"insert","lines":["    "]}],[{"start":{"row":103,"column":0},"end":{"row":103,"column":1},"action":"insert","lines":["}"],"id":359}],[{"start":{"row":102,"column":0},"end":{"row":103,"column":0},"action":"insert","lines":["",""],"id":360}],[{"start":{"row":101,"column":3},"end":{"row":102,"column":0},"action":"insert","lines":["",""],"id":361}],[{"start":{"row":12,"column":0},"end":{"row":44,"column":24},"action":"insert","lines":["var cluster  = require('cluster'), _portSocket  = 8080, _portRedis   = 6379, _HostRedis   = 'localhost';","","if (cluster.isMaster) {\t","\tvar server = require('http').createServer(), socketIO = require('socket.io').listen(server), redis = require('socket.io-redis');\t","\tsocketIO.adapter(redis({ host: _HostRedis, port: _portRedis }));","\t","\tvar numberOfCPUs = require('os').cpus().length;","\tfor (var i = 0; i < numberOfCPUs; i++) {","\t\tcluster.fork();\t\t","\t}","\t","\tcluster.on('fork', function(worker) {","        console.log('Travailleur %s créer', worker.id);","    });","    cluster.on('online', function(worker) {","         console.log('Travailleur %s en ligne', worker.id);","    });","    cluster.on('listening', function(worker, addr) {","        console.log('Travailleur %s écoute sur %s:%d', worker.id, addr.address, addr.port);","    });","    cluster.on('disconnect', function(worker) {","        console.log('Travailleur %s déconnecter', worker.id);","    });","    cluster.on('exit', function(worker, code, signal) {","        console.log('Travailleur %s mort (%s)', worker.id, signal || code);","        if (!worker.suicide) {","            console.log('Nouveau travailleur %s créer', worker.id);","            cluster.fork();","        }","    });","}","","if (cluster.isWorker) {\t"],"id":362}]]},"ace":{"folds":[],"scrolltop":240,"scrollleft":0,"selection":{"start":{"row":37,"column":38},"end":{"row":37,"column":38},"isBackwards":false},"options":{"guessTabSize":true,"useWrapMode":false,"wrapToView":true},"firstLineState":0},"timestamp":1474641146641}