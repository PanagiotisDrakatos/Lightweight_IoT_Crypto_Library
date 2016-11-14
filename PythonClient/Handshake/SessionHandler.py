import time

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
        elapsetime = int(round(time.time() * 1000))

        self._DHExchange._SynAck__SendPlainMessage()
        Execution_Time1 = int(round(time.time() * 1000))
        print("---------------Execution Time1--------------------" + str(Execution_Time1 - elapsetime))

        self._DHExchange._SynAck__ReceiveServerCertificate()
        Execution_Time2 = int(round(time.time() * 1000))
        print("---------------Execution Time2--------------------" + str(Execution_Time2 - Execution_Time1))

        self._DHExchange._SynAck__ResendCookieServer()
        Execution_Time3 = int(round(time.time() * 1000))
        print("---------------Execution Time3--------------------" + str(Execution_Time3 - Execution_Time2))

        self._DHExchange._SynAck__SendPublicValue()
        Execution_Time4 = int(round(time.time() * 1000))
        print("---------------Execution Time4--------------------" + str(Execution_Time4 - Execution_Time3))

        self._DHExchange._SynAck__ReceivePublicValue()
        Execution_Time5 = int(round(time.time() * 1000))
        print("---------------Execution Time5--------------------" + str(Execution_Time5 - Execution_Time4))

        self._DHExchange._SynAck__SendCipherSuites()
        Execution_Time6 = int(round(time.time() * 1000))
        print("---------------Execution Time6--------------------" + str(Execution_Time6 - Execution_Time5))

        SumUpTime = int(round(time.time() * 1000))
        self._ciphersforUse = self._DHExchange._SynAck__ReceiveCipherSuites()
        print("---------------DHkeys Sucessfuly Changed--------------------" + str(SumUpTime - elapsetime))

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
