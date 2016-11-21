import base64
import hashlib
from array import array

from Crypto.Cipher import AES

import pkcs7
from AesCiphers import Ciphers


class CBC(Ciphers):
    def __init__(self):
        iv = [0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]
        self.IV = array('b', iv)

    def Encrypt(self, PlainText, SecurePassword):
        pw_encode = SecurePassword.encode('utf-8')
        text_encode = PlainText.encode('utf-8')

        key = hashlib.md5(pw_encode).digest()

        cipher = AES.new(key, AES.MODE_CBC, self.IV)
        pad_text = pkcs7.encode(text_encode)
        msg = cipher.encrypt(pad_text)

        EncodeMsg = base64.b64encode(msg)
        return EncodeMsg

    def Decrypt(self, Encrypted, SecurePassword):
        decodbase64 = base64.b64decode(Encrypted.decode("utf-8"))
        pw_encode = SecurePassword.decode('utf-8')

        key = hashlib.md5(pw_encode).digest()

        cipher = AES.new(key, AES.MODE_CBC, self.IV)
        msg = cipher.decrypt(decodbase64)
        pad_text = pkcs7.decode(msg)

        decryptedString = pad_text.decode('utf-8')
        return decryptedString
