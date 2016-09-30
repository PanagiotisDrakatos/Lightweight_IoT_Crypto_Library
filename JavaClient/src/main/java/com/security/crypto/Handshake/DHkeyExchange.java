package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AesECB;
import com.security.crypto.Ciphers.AES.HMacAlgoProvider;
import com.security.crypto.Ciphers.RSA.RSA_PKCS1;
import com.security.crypto.Configuration.*;
import com.security.crypto.IOSocket.IOSynAck;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyHandler;

import java.io.IOException;
import java.math.BigInteger;
import java.util.StringJoiner;


@SuppressWarnings("ALL")
public final class DHkeyExchange extends IOSynAck {

    private IOTransport SocketChanel;
    private RandomGenerator Genarator;
    private final KeyHandler keystore;
    private AesECB aesNoIVParams;
    private RSA_PKCS1 rsa_pkcs1;
    private CookieGen cookie;
    private StringJoiner Ciphers;
    private StringJoiner Diggest;
    private StringJoiner CurrentDiggest;

    public DHkeyExchange(IOTransport SocketChanel, KeyHandler keystore) {
        this.SocketChanel = SocketChanel;
        this.cookie = new CookieGen();
        this.Genarator = new RandomGenerator();
        this.keystore = keystore;
        this.aesNoIVParams = new AesECB();
        this.rsa_pkcs1 = new RSA_PKCS1();
        Ciphers = new StringJoiner(",");
        Diggest = new StringJoiner(",");
        CurrentDiggest = new StringJoiner(",");
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
            ObjToSend.ClientEncryptedPrimeNumber = this.rsa_pkcs1.RsaEncrypt(
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
        keystore.ProduceCipherKey(sessionResult.toString());//Produce and save Ciphers Key from The given Session Result
        keystore.ProduceIntegrityKey(sessionResult.toString());//Produce and save Integrity Key from The given Session Result
        System.out.println(sessionResult.toString());
        return;
    }

    public void SendCipherSuites() throws Exception {
        JSonObject ObjToSend = new JSonObject();
        StringJoiner joiner = new StringJoiner("|");
        Ciphers.add(Properties.AES_ECB).add(Properties.AES_CBC);
        Diggest.add(Properties.MD5).add(Properties.sha1).add(Properties.MACSHA_256);
        CurrentDiggest.add(Properties.MACSHA_256);
        joiner.add(Ciphers.toString()).add(Diggest.toString()).add(CurrentDiggest.toString());

        // System.out.println(joiner.toString());
        ObjToSend.PseudoNumber = Genarator.pseudorandom();
        ObjToSend.CipherSuites = joiner.toString();
        ObjToSend.HmacHash = HMacAlgoProvider.HmacSign(joiner.toString(), keystore.loadRemoteIntegrityKey(), CurrentDiggest.toString());

        String toSend = JSonParse.WriteObject(ObjToSend);
        SocketChanel.SendMessage(toSend);
    }

    public CiphersForUse ReceiveCipherSuites() throws Exception {
        JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
        if (!receivedObj.PseudoNumber.equals(Genarator.pseudorandom()) ||
                !HMacAlgoProvider.HmacVerify(receivedObj.CipherSuites, keystore.loadRemoteIntegrityKey(), receivedObj.HmacHash, CurrentDiggest.toString()))
            throw new Exception("Server Cannot Be Verified Possible Replay Attack");


        String SelectedCiphers = receivedObj.CipherSuites;
        System.out.println(SelectedCiphers);
        String[] parts = null;

        if (SelectedCiphers.contains("|"))
            parts = SelectedCiphers.split("\\|");
        else
            throw new IllegalArgumentException("String " + SelectedCiphers + " does not contain |");

        //   System.out.println(parts.toString());
        String CipherAlgo = parts[0];
        String HashAlgo = parts[1];
        return new CiphersForUse(CipherAlgo, HashAlgo);


    }

}
