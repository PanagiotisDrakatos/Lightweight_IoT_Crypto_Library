from Ciphers.Assymmetric.RSA_PKCS1 import PCKCS1
from Ciphers.Symmetric import HmacAlgoProvider
from Ciphers.Symmetric.CiphersForUse import CipherSuite
from Configuration import Format, Properties
from Configuration.CookieGen import CookieGen
from Configuration.JsonObject import JsonObject
from Configuration.RandomGenerator import Genarator
from IOSocket.IOSynAck import SynAck
from KeyManager.DHIntegrityKey import DHIntegrity


class DiffeHelmanExhange(SynAck):
    def __init__(self, Sock, KeysHandle):
        super(SynAck, self).__init__()
        self.__Socket = Sock
        self.__StrToSend = ''
        self.__KeyHandle = KeysHandle
        self.__Generator = Genarator()
        self.__cookie = CookieGen()
        self.__rsa = PCKCS1()
        self._IntegrityKey = DHIntegrity()

    def _SynAck__SendPlainMessage(self):
        self.__ObjToSend = JsonObject()

        self.__ObjToSend.PlainMessage = Properties.SYN
        self.__ObjToSend.PseudoNumber = self.__Generator.__Pseudorandom__()

        self.__StrToSend = Format.JsonObjToStr(self.__ObjToSend)
        self.__Socket.__Send__(self.__StrToSend, 128)
        return

    def _SynAck__ReceiveServerCertificate(self):
        StrToread = self.__Socket.__Receive__()
        self.__ObjToRead = JsonObject(StrToread)
        timestamp = self.__Generator.__Pseudorandom__()
        if str(self.__ObjToRead.PlainMessage).__eq__(str(Properties.SYN_ACK)) \
                or str(self.__ObjToRead.PseudoNumber).__eq__(self, str(timestamp)):
            self.__KeyHandle._KeyManager__SaveCertificate(self.__ObjToRead.CertPemFormat)
            self.__cookie.cookieServer = self.__ObjToRead.CookieServer
        else:
            raise Exception("Server Cannot Be Verified")
        return

    def _SynAck__ResendCookieServer(self):
        self.__ObjToSend = JsonObject()

        self.__ObjToSend.PlainMessage = Properties.Replay
        self.__ObjToSend.PseudoNumber = self.__Generator.__Pseudorandom__()
        self.__ObjToSend.CookieServer = self.__cookie.cookieServer

        self.__StrToSend = Format.JsonObjToStr(self.__ObjToSend)
        self.__Socket.__Send__(self.__StrToSend, 128)
        return

    def _SynAck__SendPublicValue(self):
        self.__ObjToSend = JsonObject()
        ClientPublicPrimeNumber = self.__Generator.__PubliClientPrimeNumber__()
        self.__ObjToSend.ClientEncryptedPrimeNumber = self.__rsa.RsaEncrypt(ClientPublicPrimeNumber,
                                                                            self.__KeyHandle._KeyManager__loadRemoteServerPublicKey())
        self.__ObjToSend.PseudoNumber = self.__Generator.__Pseudorandom__()

        self.__StrToSend = Format.JsonObjToStr(self.__ObjToSend)
        self.__Socket.__Send__(self.__StrToSend, 256)
        return

    def _SynAck__ReceivePublicValue(self):
        StrToread = self.__Socket.__Receive__()
        self.__ObjToRead = JsonObject(StrToread)

        timestamp = self.__Generator.__Pseudorandom__()

        if str(self.__ObjToRead.PseudoNumber).__eq__(str(timestamp)):
            SessionResult = self.__Generator.__DHSessionPrimeNumber__(long(self.__ObjToRead.ServerPrimeNumber))
            self.__KeyHandle._KeyManager__ProduceCipherKey(SessionResult)
            self.__KeyHandle._KeyManager__ProduceIntegrityKey(SessionResult)
            # print(SessionResult)
        else:
            raise Exception("Server Cannot Be Verified Possible Replay Attack")

    def _SynAck__SendCipherSuites(self):
        self.__ObjToSend = JsonObject()
        Ciphers = [Properties.AES_CBC, Properties.AES_ECB]
        Diggest = [Properties.MD5, Properties.sha1, Properties.MACSHA_256]
        CurrentDiggest = [Properties.MACSHA_256]

        Joiner = [','.join(Ciphers), ','.join(Diggest), ','.join(CurrentDiggest)]

        self.__ObjToSend.PseudoNumber = self.__Generator.__Pseudorandom__()
        self.__ObjToSend.CipherSuites = "|".join(Joiner)
        self.Algo = CipherSuite(''.join(CurrentDiggest), "", "")
        self.__ObjToSend.HmacHash = HmacAlgoProvider.__Signature__(self.__ObjToSend.CipherSuites,
                                                                   self.__KeyHandle._KeyManager__loadRemoteIntegrityKey(),
                                                                   self.Algo.CurrentHash)

        self.__StrToSend = Format.JsonObjToStr(self.__ObjToSend)
        self.__Socket.__Send__(self.__StrToSend, 256)

    def _SynAck__ReceiveCipherSuites(self):
        StrToread = self.__Socket.__Receive__()
        self.__ObjToRead = JsonObject(StrToread)

        timestamp = self.__Generator.__Pseudorandom__()
        if str(self.__ObjToRead.PseudoNumber).__eq__(str(timestamp)):
            SelectedCiphers = str(self.__ObjToRead.CipherSuites);

            if (SelectedCiphers.__contains__("|")):
                parts = SelectedCiphers.split("|")
            else:
                raise Exception("String " + SelectedCiphers + " does not contain |")

            CipherAlgo = parts[0];
            HashAlgo = parts[1];
            return CipherSuite(None, CipherAlgo, HashAlgo)

        else:
            raise Exception("Server Cannot Be Verified")
            return null
