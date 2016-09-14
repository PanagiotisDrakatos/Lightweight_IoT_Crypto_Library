package com.security.crypto.Handshake;

import com.security.crypto.AES_Encryption.Aes_Encryption;
import com.security.crypto.AES_Encryption.HMacAlgoProvider;
import com.security.crypto.Configuration.JSonObject;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyManagerImp;
import com.security.crypto.RSA_Encryption.Fingerprint;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class IOMessageExhange implements IOCallback {

    private final KeyManagerImp keystore;
    private final IOTransport SocketChanel;

    public IOMessageExhange(IOTransport SocketChanel, KeyManagerImp keystore) {
        this.SocketChanel = SocketChanel;
        this.keystore = keystore;
    }

    @Override
    public void SendDHEncryptedMessage(String Message) {
        try {
            String encryptedMessage = (Aes_Encryption.AeS_Encrypt(Message, this.keystore.loadRemoteSecretKey().getSessionKey()));
            String HmacHash = HMacAlgoProvider.HmacSha256Sign(encryptedMessage, this.keystore.loadRemoteSecretKey().getSessionKey());

            JSonObject WriteObj = new JSonObject();

            WriteObj.setEncryptedMessage(encryptedMessage);
            WriteObj.setHmacHash(HmacHash);
            WriteObj.setFingerPrint(Fingerprint.SignData(WriteObj.getEncryptedMessage(), keystore.loadClientPrivateKey()));
            String JsonString = JSonParse.WriteObject(WriteObj);
            SocketChanel.SendMessage(JsonString);
        } catch (Exception ex) {
            Logger.getLogger(IOMessageExhange.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public String ReceiveDHEncryptedMessage() {
        try {
            JSonObject ReadObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
            if (Fingerprint.verifySig(ReadObj.getEncryptedMessage(), this.keystore.loadRemoteServerPublicKey(), ReadObj.getFingerPrint())) {
                if (HMacAlgoProvider.HmacSha256Verify(ReadObj.getEncryptedMessage(), this.keystore.loadRemoteSecretKey().getSessionKey(),
                        ReadObj.getHmacHash())) {
                    return Aes_Encryption.AeS_Decrypt(ReadObj.getEncryptedMessage(),
                            this.keystore.loadRemoteSecretKey().getSessionKey());
                } else {
                    throw new Exception("Integrity of SymmetricKey canot verified");
                }
            } else {
                throw new Exception("Integrity of RSA canot verified");
            }
        } catch (IOException ex) {
            Logger.getLogger(IOMessageExhange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(IOMessageExhange.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "Problem when receive Message";
    }

}
