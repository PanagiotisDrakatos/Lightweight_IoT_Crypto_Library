package com.security.crypto.IOSocket;

public interface IOCallback {

    void SendDHEncryptedMessage(String Message);

    String ReceiveDHEncryptedMessage();
}
