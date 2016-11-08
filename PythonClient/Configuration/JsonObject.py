from Configuration import Format


class JsonObject:
    def __init__(self, JsonStr=None):
        if JsonStr is None:
            self.PlainMessage = ""
            self.PseudoNumber = ""
            self.CookieServer = ""
            self.CertPemFormat = ""
            self.ClientEncryptedPrimeNumber = ""
            self.ServerPrimeNumber = ""
            self.CipherSuites = ""
            self.EncryptedMessage = ""
            self.FingerPrint = ""
            self.HmacHash = ""

        else:
            self.__dict__ = Format.JsonStrToOB(JsonStr)

    @property
    def PlainMessage(self):
        return self.PlainMessage

    @PlainMessage.setter
    def PlainMessage(self, value):
        self.PlainMessage = value

    @property
    def PseudoNumber(self):
        return self.PseudoNumber

    @PseudoNumber.setter
    def PseudoNumber(self, value):
        self.PseudoNumber = value

    @property
    def CookieServer(self):
        return self.CookieServer

    @CookieServer.setter
    def CookieServer(self, value):
        self.CookieServer = value

    @property
    def CertPemFormat(self):
        return self.CertPemFormat

    @CertPemFormat.setter
    def CertPemFormat(self, value):
        self.CertPemFormat = value

    @property
    def CertPemFormat(self):
        return self.CertPemFormat

    @CertPemFormat.setter
    def CertPemFormat(self, value):
        self.CertPemFormat = value

    @property
    def ClientEncryptedPrimeNumber(self):
        return self.ClientEncryptedPrimeNumber

    @ClientEncryptedPrimeNumber.setter
    def ClientEncryptedPrimeNumber(self, value):
        self.ClientEncryptedPrimeNumber = value

    @property
    def ServerPrimeNumber(self):
        return self.ServerPrimeNumber

    @ServerPrimeNumber.setter
    def ServerPrimeNumber(self, value):
        self.ServerPrimeNumber = value

    @property
    def CipherSuites(self):
        return self.CipherSuites

    @CipherSuites.setter
    def CipherSuites(self, value):
        self.CipherSuites = value

    @property
    def EncryptedMessage(self):
        return self.EncryptedMessage

    @EncryptedMessage.setter
    def EncryptedMessage(self, value):
        self.EncryptedMessage = value

    @property
    def FingerPrint(self):
        return self.FingerPrint

    @FingerPrint.setter
    def FingerPrint(self, value):
        self.FingerPrint = value

    @property
    def HmacHash(self):
        return self.HmacHash

    @HmacHash.setter
    def HmacHash(self, value):
        self.HmacHash = value
