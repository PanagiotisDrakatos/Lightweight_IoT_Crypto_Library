from Configuration import Properties
from Handshake.DHkeyExchange import DiffeHelmanExhange
from IOSocket.SSLSocket import SSLSocket
from IOSocket.Socket import PlainSocket
from KeyManager.KeyHandler import KeyHandle


class HandleSession:
    def __init__(self, ConnType):
        self._ConnType = ConnType
        self._Keystore = KeyHandle()
        self.__EstablishConn()
        self._DHExchange = DiffeHelmanExhange(self._Plain, self._Keystore)

    def __StartExhangeKey__(self):
        self._DHExchange._SynAck__SendPlainMessage()
        self._DHExchange._SynAck__ReceiveServerCertificate()
        self._DHExchange._SynAck__ResendCookieServer()
        self._DHExchange._SynAck__SendPublicValue()
        self._DHExchange._SynAck__ReceivePublicValue()
        self._DHExchange._SynAck__SendCipherSuites()
        self._ciphersforUse = self._DHExchange._SynAck__ReceiveCipherSuites()
        print("---------------DHkeys Sucessfuly Changed--------------------")

    def __EstablishConn(self):
        if str(self._ConnType).__eq__(str(Properties.Plain)):
            self._Plain = PlainSocket()
        elif str(self._ConnType).__eq__(str(Properties.Secure)):
            self._SSLSock = SSLSocket()
        else:
            raise ValueError("Not Compatible !!")

    def __Close__(self):
        try:
            self._Plain.__Close__()
        except:
            self._SSLSock
