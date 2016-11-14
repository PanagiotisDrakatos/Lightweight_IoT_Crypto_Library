from Crypto.Cipher import AES

import base64
import hashlib
import pkcs7
from AesCiphers import Ciphers


class ECB(Ciphers):
    def __init__(self):
        pass

    def Encrypt(self, PlainText, SecurePassword):
        pw_bytes = SecurePassword.encode('utf-8')
        text_bytes = PlainText.encode('utf-8')
        hash = Hash()

        key = hash.HashAlgo(pw_bytes)
        cipher = AES.new(key, AES.MODE_ECB)
        pad_text = pkcs7.encode(text_bytes)
        msg = cipher.encrypt(pad_text)
        EncodeMsg = base64.b64encode(msg).decode("utf-8")
        return EncodeMsg

    def Decrypt(self, Encrypted, SecurePassword):
        decodbase64 = base64.b64decode(Encrypted.encode("utf-8"))
        pw_bytes = SecurePassword.encode('utf-8')
        hash = Hash()

        key = hash.HashAlgo(pw_bytes)
        cipher = AES.new(key, AES.MODE_ECB)
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
