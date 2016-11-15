from Handshake.SessionHandler import HandleSession

# sessi = HandleSession("SSLSocket")
sessi = HandleSession("Plaintext")
sessi.__StartExhangeKey__()
sessi.__SendSecurMessage__("Message")
print(sessi.__ReceiveSecurMessage__())
try:
    # sessi.__StartExhangeKey__()
    sessi.__SendSecurMessage__("Messagesaddsa")
    # print(sessi.__ReceiveSecurMessage__())
except Exception as inst:
    print type(inst)
finally:
    print("closing socket")
    sessi.__Close__()
