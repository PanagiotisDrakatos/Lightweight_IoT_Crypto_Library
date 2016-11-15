import abc


class Callback(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __SendDHEncryptedMessage(self, Message, ECB):
        return

    @abc.abstractmethod
    def __SendDHEncryptedMessage(self, Message, CBC):
        return

    @abc.abstractmethod
    def __ReceiveDHEncryptedMessage(self, ECB):
        return

    @abc.abstractmethod
    def __ReceiveDHEncryptedMessage(self, CBC):
        return
