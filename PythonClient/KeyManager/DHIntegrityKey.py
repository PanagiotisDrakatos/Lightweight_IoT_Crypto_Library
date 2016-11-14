import array


class DHIntegrity:
    def __init__(self):
        self.__Session = ''
        self.__integrityKey = ''

    def __GenerateIntegrityKey__(self, SessionKey):
        self.Session = SessionKey
        data = SessionKey.encode("utf8")
        Keybytes = array.array('B', data)
        keyBytes16 = slice(min(len(Keybytes) / 2, 16), min(len(Keybytes), 32))
        self.__integrityKey = str(bytearray(Keybytes[keyBytes16]))


    @property
    def Session(self):
        return self.__Session

    @Session.setter
    def Session(self, value):
        self.__Session = value

    @property
    def integrityKey(self):
        return self.__integrityKey

    @integrityKey.setter
    def integrityKey(self, value):
        self.__integrityKey = value
