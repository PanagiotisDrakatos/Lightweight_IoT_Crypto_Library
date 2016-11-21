import os

host = "192.168.1.68"
portNumber = 1337

timeout = 0.1

PlainTextConnection = "PlainTextConnection"
SYN = "ClientHello"
SYN_ACK = "ServerHello"
Replay = "Resend"
SslTlsV2 = "SSLSocket"

exponent = "67849492012064603525502413864581601255843190582896059031333969517102908698009"
modulus = "71121776095154293411645315316982820283937449209225990596316112319337209629611"

AES_ECB = "AES/ECB/PKCS7Padding";
AES_CBC = "AES/CBC/PKCS7Padding";

MD5 = "md5"
sha1 = "SHA-1"
sha256 = "SHA-256"
MACSHA_256 = "SHA256";

RSA_Provider = "BC"
Rsa_PrivFormat = "DER"
Rsa_pubFormat = "PEM"

CHAR_ENCODING = "UTF-8"
HashingAlgorithm = "md5"

AesKeySizeLength = 64
RSA_KEYSIZE = 2048

HmacAlgProv = "HmacSHA256"
Signature = "SHA256withRSA"

keypath = os.path.abspath('./../Keystore/')
Server_PUBLIC_KEY = keypath + "/Server_Public.pem"

# -------SSL----
certpath = os.path.abspath('./../Certificates/')
Server_Cert = certpath + "/ca.crt"
Server_key = certpath + "/ca.key"
Client_Crt = certpath + "/clients.crt"
Client_key = certpath + "/ClientKey.pem"

Write = "w"
Read = "r"
Plain = "Plaintext"
Secure = "SSLSocket"
