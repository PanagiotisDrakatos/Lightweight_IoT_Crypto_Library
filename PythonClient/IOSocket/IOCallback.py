import abc


class Callback(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __SendDHEncryptedMessage(self, Message):
        return

    @abc.abstractmethod
    def __ReceiveDHEncryptedMessage(self):
        return
