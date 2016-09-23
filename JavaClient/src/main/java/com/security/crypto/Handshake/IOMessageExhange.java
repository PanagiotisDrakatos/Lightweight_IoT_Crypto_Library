package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AesNoIV_Params;
import com.security.crypto.Configuration.CiphersForUse;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyManagerImp;

public class IOMessageExhange extends IOCallback {

    private KeyManagerImp keystore = null;
    private IOTransport SocketChanel = null;
    private AesNoIV_Params aesNoIVParams = null;
    private CiphersForUse ciphersforUse = null;

    public IOMessageExhange(IOTransport SocketChanel, KeyManagerImp keystore) {
        this.SocketChanel = SocketChanel;
        this.keystore = keystore;
        this.aesNoIVParams = new AesNoIV_Params();
    }


    public void setCiphersforUse(CiphersForUse ciphersforUse) {
        this.ciphersforUse = ciphersforUse;
    }

    @Override
    public void SendDHEncryptedMessage(String Message) {

    }

    @Override
    public String ReceiveDHEncryptedMessage() {
        return "";
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
