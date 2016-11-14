import hashlib

from Crypto.Cipher import AES

from Configuration import Properties


class CipherSuite:
    def __init__(self, CurrentHash, CipherAlgorithm, HashAlgorithm):
        if CurrentHash is None:
            self.__CipherAlgorithm = self.__GetCurrentCipher(CipherAlgorithm)
            self.__HashAlgorithm = self.__GetCurrentDiggest(HashAlgorithm)
        else:
            self.__CurrentHash = self.__GetCurrentDiggest(CurrentHash)

    def __GetCurrentDiggest(self, CurrentHash):
        if CurrentHash.__eq__(Properties.MD5):
            return hashlib.md5
        elif CurrentHash.__eq__(Properties.sha1):
            return hashlib.sha1
        elif CurrentHash.__eq__(Properties.MACSHA_256):
            return hashlib.sha256
        else:
            raise ValueError("Not Compatible !!")

    def __GetCurrentCipher(self, Cipher):
        if Cipher.__eq__(Properties.AES_CBC):
            return AES.MODE_CBC
        elif Cipher.__eq__(Properties.AES_ECB):
            return AES.MODE_ECB
        else:
            raise ValueError("Not Compatible !!")

    @property
    def CipherAlgorithm(self):
        return self.__CipherAlgorithm

    @CipherAlgorithm.setter
    def CipherAlgorithm(self, value):
        self.__CipherAlgorithm = value

    @property
    def HashAlgorithm(self):
        return self.__HashAlgorithm

    @HashAlgorithm.setter
    def HashAlgorithm(self, value):
        self.__HashAlgorithm = value

    @property
    def CurrentHash(self):
        return self.__CurrentHash

    @CurrentHash.setter
    def CurrentHash(self, value):
        self.__CurrentHash = value
