class CipherSuite:
    def __init__(self):
        self.__CipherAlgorithm = ''
        self.__HashAlgorithm = ''

    def __init__(self, CipherAlgorithm, HashAlgorithm):
        self.__CipherAlgorithm = CipherAlgorithm
        self.__HashAlgorithm = HashAlgorithm

    @property
    def CipherAlgorithm(self):
        return self.CipherAlgorithm

    @CipherAlgorithm.setter
    def CipherAlgorithm(self, value):
        self.CipherAlgorithm = value

    @property
    def HashAlgorithm(self):
        return self.HashAlgorithm

    @HashAlgorithm.setter
    def HashAlgorithm(self, value):
        self.HashAlgorithm = value
