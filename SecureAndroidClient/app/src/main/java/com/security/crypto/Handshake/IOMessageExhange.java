package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AesCBC;
import com.security.crypto.Ciphers.AES.AesECB;
import com.security.crypto.Ciphers.AES.HMacAlgoProvider;
import com.security.crypto.Ciphers.RSA.Fingerprint;
import com.security.crypto.Configuration.CiphersForUse;
import com.security.crypto.Configuration.JSonObject;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyManagerImp;


public class IOMessageExhange extends IOCallback {

    private KeyManagerImp keystore = null;
    private IOTransport SocketChanel = null;
    private CiphersForUse ciphersforUse = null;

    public IOMessageExhange(IOTransport SocketChanel, KeyManagerImp keystore, CiphersForUse ciphersforUse) {
        this.SocketChanel = SocketChanel;
        this.keystore = keystore;
        this.ciphersforUse = ciphersforUse;
    }


    @Override
    public void SendDHEncryptedMessage(String Message, AesCBC CBC) throws Exception {
        JSonObject ObjToSend = new JSonObject();
        String encrypted = CBC.AeS_Encrypt(Message, keystore.loadRemoteCipherKey());
        ObjToSend.EncryptedMessage = encrypted;
        ObjToSend.HmacHash = HMacAlgoProvider.HmacSign(encrypted, keystore.loadRemoteIntegrityKey(), ciphersforUse.getHashAlgorithm());
        // System.out.println(ObjToSend.EncryptedMessage);

        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
    }

    @Override
    public void SendDHEncryptedMessage(String Message, AesECB ECB) throws Exception {
        JSonObject ObjToSend = new JSonObject();
        String encrypted = ECB.AeS_Encrypt(Message, keystore.loadRemoteCipherKey());
        ObjToSend.EncryptedMessage = encrypted;
        ObjToSend.HmacHash = HMacAlgoProvider.HmacSign(encrypted, keystore.loadRemoteIntegrityKey(), ciphersforUse.getHashAlgorithm());
        //  System.out.println(ObjToSend.EncryptedMessage);

        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
    }

    @Override
    public String ReceiveDHEncryptedMessage(AesCBC CBC) throws Exception {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        if (Fingerprint.VerifySig(receivedObj.EncryptedMessage, keystore.loadCertificate(), receivedObj.FingerPrint)) {
            if (HMacAlgoProvider.HmacVerify(receivedObj.EncryptedMessage, keystore.loadRemoteIntegrityKey(), receivedObj.HmacHash,
                    ciphersforUse.getHashAlgorithm())) {
                return CBC.AeS_Decrypt(receivedObj.EncryptedMessage,
                        keystore.loadRemoteCipherKey());
            } else {
                throw new Exception("Integrity of SymmetricKey canot verified");
            }
        } else {
            throw new Exception("Integrity of RSA canot verified");
        }

    }

    @Override
    public String ReceiveDHEncryptedMessage(AesECB ECB) throws Exception {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        if (Fingerprint.VerifySig(receivedObj.EncryptedMessage, keystore.loadCertificate(), receivedObj.FingerPrint)) {
            if (HMacAlgoProvider.HmacVerify(receivedObj.EncryptedMessage, keystore.loadRemoteIntegrityKey(), receivedObj.HmacHash,
                    ciphersforUse.getHashAlgorithm())) {
                return ECB.AeS_Decrypt(receivedObj.EncryptedMessage,
                        keystore.loadRemoteCipherKey());
            } else {
                throw new Exception("Integrity of SymmetricKey cannot verified");
            }
        } else {
            throw new Exception("Integrity of RSA cannot verified");
        }

    }

    @Override
    public String toString() {
        return super.toString();
    }
}
