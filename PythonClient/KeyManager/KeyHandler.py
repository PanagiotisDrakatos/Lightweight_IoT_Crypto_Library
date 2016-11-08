from Configuration import Properties
from KeyManager.KeyManagerImp import KeyManager


class KeyHandle(KeyManager):
    def __init__(self):
        super(KeyManager, self).__init__()
        self._CipherKey = ""
        self._IntegrityKey = ""

    def _KeyManager__SaveServerPublicKey(self):
        ServPubKey = self._KeyManager__loadCertificate()
        file = open(Properties.Server_PUBLIC_KEY, Properties.Write)
        file.write(ServPubKey)
        file.close()

    def _KeyManager__SaveCertificate(self, CertPemFormat):
        file = open(Properties.Server_Cert, Properties.Write)
        file.write(CertPemFormat)
        file.close()
        self._KeyManager__SaveServerPublicKey()
        return

    def _KeyManager__ProduceCipherKey(self, CertPemFormat):
        return

    def _KeyManager__ProduceIntegrityKey(self, SessionResult):
        return

    def _KeyManager__loadRemoteServerPublicKey(self):
        return

    def _KeyManager__loadCertificate(self):
        return

    def _KeyManager__loadRemoteCipherKey(self):
        return

    def _KeyManager__loadRemoteIntegrityKey(self):
        return
