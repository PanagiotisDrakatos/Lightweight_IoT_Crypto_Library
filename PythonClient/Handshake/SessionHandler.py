import time

from Crypto.Cipher import AES

from Ciphers.Symmetric.AesCBC import CBC
from Ciphers.Symmetric.AesECB import ECB
from Configuration import Properties
from Handshake.DHkeyExchange import DiffeHelmanExhange
from Handshake.IOMessageExchange import MessageExchange
from IOSocket.SSLSocket import SSLSocket
from IOSocket.Socket import PlainSocket
from KeyManager.KeyHandler import KeyHandle

class HandleSession:
    def __init__(self, ConnType):
        self._ConnType = ConnType
        self._Keystore = KeyHandle()
        self.__ecb = None
        self.__cbc = None
        self.__EstablishConn()

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
        print("---------------Execution Time6--------------------" + str(SumUpTime - Execution_Time6))
        print("---------------DHkeys Sucessfuly Changed--------------------" + str(SumUpTime - elapsetime))
        self._MessageExhange = MessageExchange(self._Plain, self._Keystore, self._ciphersforUse)
        self.StoreCipher()

    def StoreCipher(self):
        if self._ciphersforUse.CipherAlgorithm == AES.MODE_ECB:
            self.__ecb = ECB()
        elif self._ciphersforUse.CipherAlgorithm == AES.MODE_CBC:
            self.__cbc = CBC()

    def __SendSecurMessage__(self, Message):
        if self.__ecb is not None:
            self._MessageExhange._Callback__SendDHEncryptedMessage(Message, self.__ecb)
        elif self.__cbc is not None:
            self._MessageExhange._Callback__SendDHEncryptedMessage(Message, self.__cbc)

    def __ReceiveSecurMessage__(self):
        if self.__ecb is not None:
            return self._MessageExhange._Callback__ReceiveDHEncryptedMessage(self.__ecb)
        elif self.__cbc is not None:
            return self._MessageExhange._Callback__ReceiveDHEncryptedMessage(self.__cbc)

    def __EstablishConn(self):
        if str(self._ConnType).__eq__(str(Properties.Plain)):
            self._Plain = PlainSocket()
            self._DHExchange = DiffeHelmanExhange(self._Plain, self._Keystore)
        elif str(self._ConnType).__eq__(str(Properties.Secure)):
            self._SSLSock = SSLSocket()
        else:
            raise ValueError("Not Compatible !!")

    def __Close__(self):
        try:
            self._Plain.__Close__()
        except:
            self._SSLSock.__Close__()
