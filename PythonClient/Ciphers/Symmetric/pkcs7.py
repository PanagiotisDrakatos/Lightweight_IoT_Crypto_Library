import StringIO
import binascii


def decode(bytestring, k=16):
    nl = len(bytestring)
    val = int(binascii.hexlify(bytestring[-1]), 16)
    if val > k:
        raise ValueError('Input is not padded or padding is corrupt')

    l = nl - val
    return bytestring[:l]


def encode(bytestring, k=16):
    l = len(bytestring)
    output = StringIO.StringIO()
    val = k - (l % k)
    for _ in xrange(val):
        output.write('%02x' % val)
    return bytestring + binascii.unhexlify(output.getvalue())
