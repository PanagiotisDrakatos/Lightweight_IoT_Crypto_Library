import array
import math


class DHCipher:
    def __init__(self):
        self.__Session = ''
        self.__CipherKey = ''

    def __GenerateCipherKey__(self, SessionKey):
        self.Session = SessionKey
        try:
            data = SessionKey.decode("utf8")
            array.array('B', data)
            keyBytes16 = slice(0, math.min(len(array) / 2, 16))
            self.integrityKey = str(bytearray(keyBytes16))
        except Exception as inst:
            print type(inst)

    @property
    def Session(self):
        return self.Session

    @Session.setter
    def Session(self, value):
        self.Session = value

    @property
    def CipherKey(self):
        return self.CipherKey

    @CipherKey.setter
    def CipherKey(self, value):
        self.CipherKey = value
