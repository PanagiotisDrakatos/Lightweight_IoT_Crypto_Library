import base64
import binascii
import json
from binascii import a2b_base64


def bin2hex(binStr):
    return binascii.hexlify(binStr)


def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)


def PemtoDer(pem):
    lines = pem.replace(" ", '').split()
    der = a2b_base64(''.join(lines[1:-1]))
    toBase64 = base64.b64encode(der).decode("utf-8")
    return toBase64


def JsonObjToStr(objvalue):
    return json.dumps(objvalue.__dict__)


def JsonStrToOB(strvalue):
    return json.loads(strvalue)
