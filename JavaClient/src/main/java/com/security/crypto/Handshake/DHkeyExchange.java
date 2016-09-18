package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AES_ECB_PKCS7;
import com.security.crypto.Ciphers.RSA.RSA_ECB_PKCS1;
import com.security.crypto.Configuration.CookieGen;
import com.security.crypto.Configuration.JSonObject;
import com.security.crypto.Configuration.Properties;
import com.security.crypto.Configuration.RandomGenerator;
import com.security.crypto.IOSocket.IOSynAck;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyManagerImp;

import java.io.IOException;
import java.math.BigInteger;

public final class DHkeyExchange extends IOSynAck {

    private final IOTransport SocketChanel;
    private final RandomGenerator Genarator;
    private final KeyManagerImp keystore;
    private AES_ECB_PKCS7 aes_ecb_pkcs7;
    private RSA_ECB_PKCS1 rsa_ecb_pkcs1;
    private CookieGen cookie;

    public DHkeyExchange(IOTransport SocketChanel, KeyManagerImp keystore) {
        this.SocketChanel = SocketChanel;
        this.Genarator = new RandomGenerator();
        this.keystore = keystore;
        this.aes_ecb_pkcs7 = new AES_ECB_PKCS7();
        this.rsa_ecb_pkcs1 = new RSA_ECB_PKCS1();
    }

    @Override
    public void SendPlainMessage() throws IOException {
        //send PublicKey to Server
        JSonObject ObjToSend = new JSonObject();
        ObjToSend.PlainMessage = Properties.SYN;
        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
    }

    public void ReceiveServerCertificate() throws Exception {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        if (receivedObj.PlainMessage == Properties.SYN_ACK)
            throw new Exception("Server Cannot Be Verified");
        else
            this.keystore.saveCertificate(receivedObj.CertPemFormat);
        cookie.setCookieServer(receivedObj.CookieServer);
        return;
    }

    public void ResendCookieServer() throws IOException {
        JSonObject ObjToSend = new JSonObject();
        ObjToSend.PlainMessage = Properties.Replay;
        ObjToSend.CookieServer = this.cookie.getCookieServer();
        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
        return;
    }


    public void SendPublicValue() throws IOException {
        BigInteger ServerPublicPrimeNumber = Genarator.GeneratePublicPrimeNumber();
        JSonObject ObjToSend = new JSonObject();
        try {
            ObjToSend.ClientEncryptedPrimeNumber = this.rsa_ecb_pkcs1.RsaEncrypt(
                    keystore.loadRemoteServerPublicKey(), ServerPublicPrimeNumber.toString());

            String toSend = JSonParse.WriteObject(ObjToSend);
            SocketChanel.SendMessage(toSend);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void ReceivePublicValue() throws IOException {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        BigInteger sessionResult = Genarator.SessionGenerator(receivedObj.ServerPrimeNumber);
        keystore.saveSecretKey(sessionResult.toString());
        return;
    }

}
