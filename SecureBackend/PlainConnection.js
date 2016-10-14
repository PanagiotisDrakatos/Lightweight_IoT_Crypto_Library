'use strict';

//npm install -g node-gyp
//npm install ursa

//npm install bluebird
//npm install mkdirp@latest

//npm install node-forge
//npm install big-integer

//npm install mongodb

var _HOST = '192.168.1.67';
var _PORT = 1337;
var _address;

var net = require('net');
var userCount = 0;
const BasicProtocolEmmitter = require("./IOTransports");
var ProtocolEmmitter = new BasicProtocolEmmitter();

var server = net.createServer(function(socket) {
    socket.on('connect', (e) => {
        console.log('client connected ' +
            socket.remoteAddress + ':' +
            socket.remotePort);
    });

    socket.on('data', function(data) {
        console.log('clients says' + ': ' + data);
        userCount++;
        ProtocolEmmitter.Receive(data);
        // socket.pipe(socket);
        if (userCount != 2) {
            var send = ProtocolEmmitter.send();
          // console.log('Server says' + ': ' + send);
            socket.write(send + '\n');
        }

    });

    socket.on('error', function(data) {
        console.log('client on error', data);
        ProtocolEmmitter = new BasicProtocolEmmitter();
        userCount = 0;
    });

    socket.on('close', (e) => {
        console.log('client disconnected');
        socket.end;
        ProtocolEmmitter = new BasicProtocolEmmitter();
        userCount = 0;
    });

});
server.on('Error', (e) => {
    if (e.code == 'EADDRINUSE') {
        console.log('Address alredy bind  retrying...');
        setTimeout(() => {
            server.close();
            server.listen(_PORT, _HOST);
        }, 10000);
    }
});

server.listen(_PORT, _HOST, () => {
    _address = server.address();
    console.log('opened server on %j', _address);
    console.log(' Server listening on %j ', _HOST, ':', _PORT);
});