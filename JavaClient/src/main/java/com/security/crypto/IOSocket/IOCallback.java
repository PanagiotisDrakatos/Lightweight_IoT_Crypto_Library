package com.security.crypto.IOSocket;


import com.security.crypto.Ciphers.AES.AesCBC;
import com.security.crypto.Ciphers.AES.AesECB;

public abstract class IOCallback {

    public abstract void SendDHEncryptedMessage(String Message, AesECB ecb) throws Exception;

    public abstract void SendDHEncryptedMessage(String Message, AesCBC cbc) throws Exception;

    public abstract String ReceiveDHEncryptedMessage(AesECB ecb) throws Exception;

    public abstract String ReceiveDHEncryptedMessage(AesCBC cbc) throws Exception;

}
