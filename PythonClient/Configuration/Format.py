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
    return der


def JsonObjToStr(objvalue):
    json_string = json.dumps(objvalue.__dict__, ensure_ascii=False).encode('utf8')
    return json_string


def JsonStrToOB(strvalue):
    return json.loads(strvalue, object_hook=ascii_encode_dict)


def ascii_encode_dict(data):
    ascii_encode = lambda x: x.encode('ascii')
    return dict(map(ascii_encode, pair) for pair in data.items())
