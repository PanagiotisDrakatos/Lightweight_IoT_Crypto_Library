package com.security.crypto.IOSocket;

public interface IOSynAck {

    void SendClientPublicKey();

    void ReceiveServerPublicKey();

    String SendPrimeNumber();

    void EndDHsession();

}
