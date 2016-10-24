var _HOST = '192.168.1.67';
var _PORT = 1337;
var _address;

const tls = require('tls');
const fs = require('fs');

const options = {
    // These are necessary only if using the client certificate authentication
    key: fs.readFileSync('./Certs/ca.key'),
    cert: fs.readFileSync('./Certs/ca.crt'),
    //ca: [fs.readFileSync('./Certs/smclient_cert.pem')],
    requestCert: false,
    passphrase: 'password',
};

const BasicProtocolEmmitter = require("./IOTransports");

var server = tls.createServer(options, (socket) => {
    const ProtocolEmmitter = new BasicProtocolEmmitter();
    
    socket.on('connect', (e) => {
        console.log('client connected ' +
            socket.remoteAddress + ':' +
            socket.remotePort);
    });

    socket.on('data', function(data) {
        console.log('clients says' + ': ' + data);
        ProtocolEmmitter.Receive(data);
        // socket.pipe(socket);
        var send = ProtocolEmmitter.send();
        console.log(send);
        socket.write(send + '\n');
        //  socket.pipe(socket);

    });

    socket.on('error', function(data) {
        console.log('client on error', data);

    });

    socket.on('close', (e) => {
        console.log('client disconnected');
        socket.end;
        setTimeout(() => {
            server.close();
            server.listen(_PORT, _HOST, () => {
                _address = server.address();
                console.log('opened server on %j', _address);
                console.log(' Server listening on %j ', _HOST, ':', _PORT);
            });
        }, 10000);
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