package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AesNoIV_Params;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyManagerImp;

public class IOMessageExhange extends IOCallback {

    private final KeyManagerImp keystore;
    private final IOTransport SocketChanel;
    private AesNoIV_Params aesNoIVParams;

    public IOMessageExhange(IOTransport SocketChanel, KeyManagerImp keystore) {
        this.SocketChanel = SocketChanel;
        this.keystore = keystore;
        this.aesNoIVParams = new AesNoIV_Params();
    }

    @Override
    public void SendDHEncryptedMessage(String Message) {

    }

    @Override
    public String ReceiveDHEncryptedMessage() {
        return "";
    }

}
