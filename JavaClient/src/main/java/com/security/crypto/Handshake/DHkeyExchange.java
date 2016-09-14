package com.security.crypto.Handshake;

import com.security.crypto.AES_Encryption.Aes_Encryption;
import com.security.crypto.AES_Encryption.HMacAlgoProvider;
import com.security.crypto.Configuration.JSonObject;
import com.security.crypto.Configuration.RandomGenerator;
import com.security.crypto.IOSocket.IOSynAck;
import com.security.crypto.IOSocket.IOTransport;
import com.security.crypto.KeyManager.KeyManagerImp;
import com.security.crypto.RSA_Encryption.Fingerprint;
import com.security.crypto.RSA_Encryption.RSA_Encryption;

import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DHkeyExchange implements IOSynAck {

    private final IOTransport SocketChanel;
    private final RandomGenerator Genarator;
    private final KeyManagerImp keystore;

    public DHkeyExchange(IOTransport SocketChanel, KeyManagerImp keystore) {
        this.SocketChanel = SocketChanel;
        this.Genarator = new RandomGenerator();
        this.keystore = keystore;
    }

    @Override
    public void SendClientPublicKey() {
        try {
            //send PublicKey to Server
            JSonObject ObjToSend = new JSonObject();
            ObjToSend.setRSAPublicKey(keystore.loadStringFormatClientPublicKey());
            System.out.println("pub key to send " + ObjToSend.getRSAPublicKey());
            String toSend = JSonParse.WriteObject(ObjToSend);
            SocketChanel.SendMessage(toSend);

            System.out.println("Server----------------(publicKey)---------->Client");
        } catch (IOException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //More readable is more efficient. Temporary expressions and local variables need the same space and
    //from CPU/JVM perspective it doesn't make much difference. JVM will do a better job 
    //optimizing/inling it
    @Override
    public void ReceiveServerPublicKey() {
        try {
            //Client  Receives Public Key From server
            JSonObject receivedObj = JSonParse.ReadObject(SocketChanel.receiveMessage());
            keystore.saveServerPublicKey(receivedObj.getRSAPublicKey());
            System.out.println(keystore.loadRemoteServerPublicKey());
        } catch (IOException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @Override
    public String SendPrimeNumber() {

        try {
            BigInteger ServerPublicPrimeNumber = Genarator.GeneratePublicPrimeNumber();

            System.out.println(keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat());
            String ClientEncryptedPrimeNumber = Aes_Encryption.AeS_Encrypt(ServerPublicPrimeNumber.toString(), keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat());
            String HmacHash = HMacAlgoProvider.HmacSha256Sign(ClientEncryptedPrimeNumber, keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat());

            JSonObject ObjToSend = new JSonObject();

            ObjToSend.setClientEncryptedPrimeNumber(ClientEncryptedPrimeNumber);
            ObjToSend.setClientKey(keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat());
            ObjToSend.setHmacHash(HmacHash);
            ObjToSend.setEncryptedSymetricClientKey(RSA_Encryption.RsaEecrypt(keystore.loadRemoteServerPublicKey(), keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat()));
            ObjToSend.setFingerPrint(Fingerprint.SignData(ObjToSend.getEncryptedSymetricClientKey(), keystore.loadClientPrivateKey()));

            String JsonString = JSonParse.WriteObject(ObjToSend);

            SocketChanel.SendMessage(JsonString);
            return "";
        } catch (Exception ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    @Override
    public void EndDHsession() {
        try {
            String sd = SocketChanel.receiveMessage();
            System.out.println(sd);
            JSonObject receivedObj = JSonParse.ReadObject(sd);
            String DecryptedServerNumber;

            if (Fingerprint.verifySig(receivedObj.getServerPrimeNumber(), keystore.loadRemoteServerPublicKey(), receivedObj.getFingerPrint())) {
                if (HMacAlgoProvider.HmacSha256Verify(receivedObj.getServerPrimeNumber(), keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat(),
                        receivedObj.getHmacHash())) {
                    DecryptedServerNumber = Aes_Encryption.AeS_Decrypt(receivedObj.getServerPrimeNumber(),
                            keystore.loadRemoteSymetricKey().getBase64SymetriKeyFormat());
                    BigInteger sessionResult = Genarator.SessionGenerator(DecryptedServerNumber);
                    keystore.saveSecretKey(sessionResult.toString());

                } else {
                    throw new Exception("Integrity of SymmetricKey Canot Verified");
                }
            } else {
                throw new Exception("Integrity of Signature  Can not be Verified");
            }
        } catch (IOException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
