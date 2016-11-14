import base64

from Crypto.Util.asn1 import DerSequence

from Configuration import Properties, Format
from DHCipherKey import DHCipher
from DHIntegrityKey import DHIntegrity
from KeyManager.KeyManagerImp import KeyManager


class KeyHandle(KeyManager):
    def __init__(self):
        super(KeyManager, self).__init__()
        self.__Start_Replace = "-----BEGIN CERTIFICATE-----"
        self.__End_Replace = "-----END CERTIFICATE----"
        self._CipherKey = DHCipher()
        self._IntegrityKey = DHIntegrity()

    def _KeyManager__SaveServerPublicKey(self):
        Certx509 = self._KeyManager__loadCertificate()

        tbsCertificate = DerSequence()
        tbsCertificate.decode(Certx509[0])
        subjectPublicKeyInfo = tbsCertificate[6]

        PubPem = base64.b64encode(subjectPublicKeyInfo)
        file = open(Properties.Server_PUBLIC_KEY, Properties.Write)
        file.write(PubPem)
        file.close()

    def _KeyManager__SaveCertificate(self, CertPemFormat):
        file = open(Properties.Server_Cert, Properties.Write)
        cert = self.__Start_Replace + "\n" + CertPemFormat + "\n" + self.__End_Replace
        file.write(cert)
        file.close()
        self._KeyManager__SaveServerPublicKey()
        return

    def _KeyManager__loadRemoteServerPublicKey(self):
        file = open(Properties.Server_PUBLIC_KEY, Properties.Read)
        PubPem = file.read()
        PubKey = base64.b64decode(PubPem)
        # rsa_key = RSA.importKey(PubKey)
        file.close()
        return PubKey

    def _KeyManager__loadCertificate(self):
        file = open(Properties.Server_Cert, Properties.Read)
        CertPem = file.read()
        der = Format.PemtoDer(CertPem)
        cert = DerSequence()
        cert.decode(der)
        file.close()
        return cert

    def _KeyManager__ProduceCipherKey(self, SessionResult):
        self._CipherKey.__GenerateCipherKey__(SessionResult)

    def _KeyManager__ProduceIntegrityKey(self, SessionResult):
        self._IntegrityKey.__GenerateCipherKey__(SessionResult)

    def _KeyManager__loadRemoteCipherKey(self):
        return self._CipherKey.CipherKey

    def _KeyManager__loadRemoteIntegrityKey(self):
        return self._IntegrityKey.integrityKey
