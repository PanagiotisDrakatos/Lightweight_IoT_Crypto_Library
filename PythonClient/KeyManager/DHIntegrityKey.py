import array
import math


class DHIntegrity:
    def __init__(self):
        self.__Session = ''
        self.__integrityKey = ''

    def __GenerateIntegrityKey__(self, SessionKey):
        self.Session = SessionKey
        try:
            data = SessionKey.decode("utf8")
            array.array('B', data)
            keyBytes16 = slice(math.min(len(array) / 2, 16), math.min(len(array), 32))
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
    def integrityKey(self):
        return self.integrityKey

    @integrityKey.setter
    def integrityKey(self, value):
        self.integrityKey = value
