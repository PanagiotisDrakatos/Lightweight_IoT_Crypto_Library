import socket

from IOSocket.IOTransport import IoTransport


class PlainSocket(IoTransport):
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        super(PlainSocket, self).__init__(self._sock)

    def __Send__(self, msg):
        super(PlainSocket, self).__Send__(msg)

    def __Receive__(self):
        return super(PlainSocket, self).__Receive__()

    def __Close__(self):
        super(PlainSocket, self).__Close__()

    @property
    def Socket(self):
        return self._sock
