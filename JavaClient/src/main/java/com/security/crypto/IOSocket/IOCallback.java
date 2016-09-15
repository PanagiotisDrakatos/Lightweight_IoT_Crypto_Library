package com.security.crypto.IOSocket;

public abstract class IOCallback {

    public abstract void SendDHEncryptedMessage(String Message);

    public abstract String ReceiveDHEncryptedMessage();
}
