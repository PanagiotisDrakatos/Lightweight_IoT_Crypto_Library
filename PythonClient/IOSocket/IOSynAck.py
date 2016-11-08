import abc


class SynAck(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __SendPlainMessage(self):
        return

    @abc.abstractmethod
    def __ReceiveServerCertificate(self):
        return

    @abc.abstractmethod
    def __ResendCookieServer(self):
        return

    @abc.abstractmethod
    def __SendPublicValue(self):
        return

    @abc.abstractmethod
    def __ReceivePublicValue(self):
        return

    @abc.abstractmethod
    def __SendCipherSuites(self):
        return

    @abc.abstractmethod
    def __ReceiveCipherSuites(self):
        return
