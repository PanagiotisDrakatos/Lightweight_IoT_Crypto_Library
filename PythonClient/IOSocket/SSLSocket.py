import socket
import ssl

from Configuration import Properties
from IOSocket.IOTransport import IoTransport


class SSLSocket(IoTransport):
    def __init__(self):
        Context = self.__loadContext()
        self._SSL_Sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                         ca_certs=Properties.Server_Cert,
                                         cert_reqs=ssl.CERT_REQUIRED,
                                         ssl_version=ssl.PROTOCOL_TLSv1)
        super(SSLSocket, self).__init__(self._SSL_Sock)

    def __loadContext(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        return context

    def __connect(self, host, port):
        super(SSLSocket, self).__connect()

    def __Send__(self, msg, MSGLEN):
        super(SSLSocket, self).__Send__(msg, MSGLEN)

    def __Receive__(self):
        return super(SSLSocket, self).__Receive__()

    def __Close__(self):
        super(SSLSocket, self).__Close__()

    @property
    def Socket(self):
        return self._sock
