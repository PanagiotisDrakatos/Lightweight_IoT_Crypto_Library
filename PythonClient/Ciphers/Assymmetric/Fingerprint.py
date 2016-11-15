import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def __Signature__(Encrypted, PrivateKey):
    privkey = RSA.importKey(PrivateKey)
    hash = SHA256.new(Encrypted)
    signer = PKCS1_v1_5.new(privkey)
    signature = signer.sign(hash)
    sigTobase64 = base64.b64encode(signature)
    return sigTobase64;


def __verification__(Encrypted, publicKey, ServerSig):
    pubkey = RSA.importKey(publicKey)
    hash = SHA256.new(Encrypted)
    verifier = PKCS1_v1_5.new(pubkey)
    ServerSigBase64 = base64.b64decode(ServerSig)
    if verifier.verify(hash, ServerSigBase64):
        print "The signature is authentic."
        return True
    else:
        raise ValueError("The signature is not authentic")
