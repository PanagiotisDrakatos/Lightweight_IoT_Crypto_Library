import array


class DHCipher:
    def __init__(self):
        self.__Session = ''
        self.__CipherKey = ''

    def __GenerateCipherKey__(self, SessionKey):
        self.Session = SessionKey
        data = SessionKey.encode("utf8")
        Keybytes = array.array('B', data)
        keyBytes16 = slice(0, min(len(Keybytes) / 2, 16))
        self.__CipherKey = str(bytearray(Keybytes[keyBytes16]))

    @property
    def Session(self):
        return self.__Session

    @Session.setter
    def Session(self, value):
        self.__Session = value

    @property
    def CipherKey(self):
        return self.__CipherKey

    @CipherKey.setter
    def CipherKey(self, value):
        self.__CipherKey = value
