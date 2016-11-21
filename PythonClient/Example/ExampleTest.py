from Handshake.SessionHandler import HandleSession

# elapsetime = int(round(time.time() * 1000))

# sessi = HandleSession("SSLSocket")
# Execution_Time1 = int(round(time.time() * 1000))-elapsetime
# print("---------------Execution Time--------------------" + str(Execution_Time1))

sessi = HandleSession("Plaintext")
try:
    sessi.__StartExhangeKey__()

    sessi.__SendSecurMessage__("Message")
    print(sessi.__ReceiveSecurMessage__())

    sessi.__SendSecurMessage__("Message1")
    print(sessi.__ReceiveSecurMessage__())
except Exception as inst:
    print type(inst)
finally:
    print("closing socket")
    sessi.__Close__()
