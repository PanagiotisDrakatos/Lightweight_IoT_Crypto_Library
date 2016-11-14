import socket
import time

from Configuration import Properties


class IoTransport(object):
    def __init__(self, sock=None):
        self._MSGLEN = 256
        if sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__connect(Properties.host, Properties.portNumber)
        else:
            self._sock = sock
            self.__connect(Properties.host, Properties.portNumber)

    def __connect(self, host, port):
        try:
            self._sock.connect((host, port))
        except Exception as e:
            print("something's wrong with %s:%d. Exception is %s" % (host, port, e))
            self._sock.close()

    def __Send__(self, msg, MSGLEN):
        totalsent = 0
        while totalsent < MSGLEN:
            sent = self._sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def __Receive__(self):
        self._sock.setblocking(0)
        total_data = [];
        begin = time.time()
        while 1:
            if total_data and time.time() - begin > Properties.timeout:
                break
            elif time.time() - begin > Properties.timeout * 2:
                break
            try:
                data = self._sock.recv(8192)
                if data:
                    total_data.append(data)
                    begin = time.time()
                else:
                    time.sleep(0.1)
            except:
                pass
        return ''.join(total_data)

    @property
    def Socket(self):
        return self._sock

    def __Close__(self):
        self._sock.close()
