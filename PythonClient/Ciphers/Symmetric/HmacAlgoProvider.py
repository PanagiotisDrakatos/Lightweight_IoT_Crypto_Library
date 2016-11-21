import base64
import hmac


def __Signature__(EncryptedMessage, Password, CurrentDiggest):
    pw_bytes = Password.encode('utf-8')
    text_bytes = EncryptedMessage.encode('utf-8')
    Plainmac = hmac.new(pw_bytes, text_bytes, digestmod=CurrentDiggest).digest()
    EncodedHmac = base64.b64encode(Plainmac)
    # print("hmac ", EncodedHmac.decode("utf-8"))
    return EncodedHmac.decode("utf-8")


def __HmacVerify__(EncryptedMessage, Password, SenderHmac, CurrentDiggest):
    CurrentHmac = __Signature__(EncryptedMessage, Password, CurrentDiggest)
    if CurrentHmac.__eq__(SenderHmac):
        print("Hmac Integrity Verifierd Succesfylly !!")
        return True

    else:
        print("Hmac Cannot be verified !!")
        raise ValueError("Hmac Cannot be verified !!")
