class CookieGen:
    def __init__(self):
        self.DEF_RANDOM_ALGORITHM = "SHA1PRNG"
        self.seedByteCount = 10
        self.cookieServer = ""

    @property
    def cookieServer(self):
        return self.cookieServer

    @cookieServer.setter
    def cookieServer(self, value):
        self.cookieServer = value
