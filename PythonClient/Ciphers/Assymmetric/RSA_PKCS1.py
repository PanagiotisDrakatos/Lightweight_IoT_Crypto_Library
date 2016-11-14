import base64

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

from Ciphers.Assymmetric.RsaCiphers import RSA_Cipher


class PCKCS1(RSA_Cipher):
    def __init__(self):
        pass

    def RsaEncrypt(self, Message, PublicKey):
        text_bytes = Message.encode('utf-8')
        h = SHA.new(text_bytes)
        pubkey = RSA.importKey(PublicKey)
        cipher = PKCS1_v1_5.new(pubkey)
        ciphertext = cipher.encrypt(text_bytes)  # +h.digest
        Encodeciphertext = base64.b64encode(ciphertext).decode("utf-8")
        return Encodeciphertext

    def RsaDecrypt(self, EncryptedMessage, PrivateKey):
        decodeEncrypted = base64.b64decode(EncryptedMessage.encode("utf-8"))
        privkey = RSA.importKey(PrivateKey)
        dsize = SHA.digest_size
        sentinel = Random.new().read(15 + dsize)
        cipher = PKCS1_v1_5.new(privkey)  # +sentinel
        message = cipher.decrypt(decodeEncrypted, sentinel)
        return message
