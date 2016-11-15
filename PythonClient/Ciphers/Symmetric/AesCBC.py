import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES

import pkcs7
from AesCiphers import Ciphers


class CBC(Ciphers):
    def __init__(self):
        self.iv = "0x15, 0x14, 0x13, 0x12, 0x11,0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00"

    def Encrypt(self, PlainText, SecurePassword):
        pw_bytes = SecurePassword.encode('utf-8')
        text_bytes = PlainText.encode('utf-8')
        hash = Hash()
        key = hash.HashAlgo(pw_bytes)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_text = pkcs7.encode(text_bytes)
        msg = iv + cipher.encrypt(pad_text)
        EncodeMsg = base64.b64encode(msg).encode("utf-8")
        return EncodeMsg

    def Decrypt(self, Encrypted, SecurePassword):
        decodbase64 = base64.b64decode(Encrypted.decode("utf-8"))
        pw_bytes = SecurePassword.decode('utf-8')
        hash = Hash()
        iv = decodbase64[:AES.block_size]
        key = hash.HashAlgo(pw_bytes)
        cipher = AES.new(key, AES.MODE_ECB, iv)
        msg = cipher.decrypt(decodbase64)
        pad_text = pkcs7.decode(msg)
        decryptedString = pad_text.decode('utf-8')
        return decryptedString;


class Hash:
    def HashAlgo(self, pwBytes):
        m = hashlib.md5()
        m.update(pwBytes)
        key = m.digest()
        return key;
