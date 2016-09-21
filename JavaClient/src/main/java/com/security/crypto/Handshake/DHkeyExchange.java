package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AesNoIV_Params;
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
    private AesNoIV_Params aesNoIVParams;
    private RSA_ECB_PKCS1 rsa_ecb_pkcs1;
    private CookieGen cookie;

    public DHkeyExchange(IOTransport SocketChanel, KeyManagerImp keystore) {
        this.SocketChanel = SocketChanel;
        this.cookie = new CookieGen();
        this.Genarator = new RandomGenerator();
        this.keystore = keystore;
        this.aesNoIVParams = new AesNoIV_Params();
        this.rsa_ecb_pkcs1 = new RSA_ECB_PKCS1();
    }

    @Override
    public void SendPlainMessage() throws IOException {
        //send PublicKey to Server
        JSonObject ObjToSend = new JSonObject();
        ObjToSend.PlainMessage = Properties.SYN;
        ObjToSend.PseudoNumber = Genarator.pseudorandom();
        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
    }

    public void ReceiveServerCertificate() throws Exception {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        String timestamp = Genarator.pseudorandom();
        if (!receivedObj.PlainMessage.equals(Properties.SYN_ACK) ||
                !receivedObj.PseudoNumber.equals(timestamp))
            throw new Exception("Server Cannot Be Verified");
        else
            this.keystore.SaveCertificate(receivedObj.CertPemFormat);
        cookie.setCookieServer(receivedObj.CookieServer);
        return;
    }

    public void ResendCookieServer() throws IOException {
        JSonObject ObjToSend = new JSonObject();
        ObjToSend.PlainMessage = Properties.Replay;
        ObjToSend.PseudoNumber = Genarator.pseudorandom();
        ObjToSend.CookieServer = this.cookie.getCookieServer();
        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
        return;
    }


    public void SendPublicValue() throws IOException {
        BigInteger ServerPublicPrimeNumber = Genarator.GeneratePublicPrimeNumber();
        try {
            JSonObject ObjToSend = new JSonObject();
            ObjToSend.PseudoNumber = Genarator.pseudorandom();
            ObjToSend.ClientEncryptedPrimeNumber = this.rsa_ecb_pkcs1.RsaEncrypt(
                    keystore.loadRemoteServerPublicKey(), ServerPublicPrimeNumber.toString());

            String toSend = JSonParse.WriteObject(ObjToSend);
            SocketChanel.SendMessage(toSend);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void ReceivePublicValue() throws Exception {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        if (!receivedObj.PseudoNumber.equals(Genarator.pseudorandom()))
            throw new Exception("Server Cannot Be Verified Possible Replay Attack");

        BigInteger sessionResult = Genarator.SessionGenerator(receivedObj.ServerPrimeNumber);
        keystore.ProduceCipherKey(sessionResult.toString());//Produce and save Cipher Key from The given Session Result
        keystore.ProduceIntegrityKey(sessionResult.toString());//Produce and save Integrity Key from The given Session Result
        System.out.println(sessionResult.bitLength());
        return;
    }

}
