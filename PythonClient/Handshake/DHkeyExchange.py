from Configuration import Format, Properties
from Configuration.CookieGen import CookieGen
from Configuration.JsonObject import JsonObject
from Configuration.RandomGenerator import Genarator
from IOSocket.IOSynAck import SynAck


class DiffeHelmanExhange(SynAck):
    def __init__(self, Sock, KeysHandle):
        super(SynAck, self).__init__()
        self.__Socket = Sock
        self.__StrToSend = ''
        self.__KeyHandle = KeysHandle
        self.__Generator = Genarator()
        self.__cookie = CookieGen()

    def _SynAck__SendPlainMessage(self):
        self.__ObjToSend = JsonObject()

        self.__ObjToSend.PlainMessage = Properties.SYN
        self.__ObjToSend.PseudoNumber = self.__Generator.__Pseudorandom__()

        self.__StrToSend = Format.JsonObjToStr(self.__ObjToSend)
        self.__Socket.__Send__(self.__StrToSend)
        return

    def _SynAck__ReceiveServerCertificate(self):
        StrToread = self.__Socket.__Receive__()
        self.__ObjToRead = JsonObject(StrToread)

        timestamp = self.__Generator.__Pseudorandom__()
        if str(self.__ObjToRead.PlainMessage).__eq__(self, str(Properties.SYN_ACK)) \
                or str(self.__ObjToRead.PseudoNumber).__eq__(self, str(timestamp)):
            self.__KeyHandle.SaveCertificate(self.__ObjToRead.CertPemFormat)
            self.__cookie.cookieServer = self.__ObjToRead.CookieServer
        else:
            raise Exception("Server Cannot Be Verified")
        return

    def _SynAck__ResendCookieServer(self):
        self.__ObjToSend = JsonObject()

        self.__ObjToSend.PlainMessage = Properties.Replay
        self.__ObjToSend.PseudoNumber = self.__Generator.__Pseudorandom()
        self.__ObjToSend.CookieServer = self.__cookie.cookieServer

        self.__StrToSend = Format.JsonObjToStr(self.__ObjToSend)
        self.__Socket.__Send__(self.__StrToSend)
        return

    def _SynAck__SendPublicValue(self):
        self.__ObjToSend = JsonObject()
        return

    def _SynAck__ReceivePublicValue(self):
        return

    def _SynAck__SendCipherSuites(self):
        return

    def _SynAck__ReceiveCipherSuites(self):
        return
