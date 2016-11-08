import abc


class IOCallback(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def SendDHEncryptedMessage(self, Message):
        return

    @abc.abstractmethod
    def ReceiveDHEncryptedMessage(self):
        return
