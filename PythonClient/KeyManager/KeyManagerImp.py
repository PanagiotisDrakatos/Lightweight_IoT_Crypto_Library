import abc


class KeyManager(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __SaveServerPublicKey(self):
        return

    @abc.abstractmethod
    def __SaveCertificate(self, CertPemFormat):
        return

    @abc.abstractmethod
    def __ProduceCipherKey(self, CertPemFormat):
        return

    @abc.abstractmethod
    def __ProduceIntegrityKey(self, SessionResult):
        return

    @abc.abstractmethod
    def __loadRemoteServerPublicKey(self):
        return

    @abc.abstractmethod
    def __loadCertificate(self):
        return

    @abc.abstractmethod
    def __loadRemoteCipherKey(self):
        return

    @abc.abstractmethod
    def __loadRemoteIntegrityKey(self):
        return
