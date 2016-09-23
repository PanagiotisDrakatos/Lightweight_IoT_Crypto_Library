package com.security.crypto.Handshake;

import com.security.crypto.Configuration.CiphersForUse;
import com.security.crypto.IOSocket.EstablishConnection;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOSynAck;
import com.security.crypto.KeyManager.KeyHandler;
import com.security.crypto.KeyManager.KeyManagerImp;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SessionHandler {

    private EstablishConnection Session = null;
    private KeyManagerImp keystore = null;

    private IOSynAck keyExchange = null;
    private IOCallback MessageExhange = null;
    private CiphersForUse ciphersforUse = null;


    public SessionHandler(String connection) {
        this.Session = new EstablishConnection(connection);
        this.keystore = new KeyHandler();
        this.keyExchange = new DHkeyExchange(this.Session.getTransport(), this.keystore);
        this.MessageExhange = new IOMessageExhange(this.Session.getTransport(), this.keystore);
    }

    public SessionHandler(String connection, int timeout) {
        this.Session = new EstablishConnection(connection, timeout);
        this.keystore = new KeyHandler();
        this.keyExchange = new DHkeyExchange(this.Session.getTransport(), this.keystore);
        this.MessageExhange = new IOMessageExhange(this.Session.getTransport(), this.keystore);
    }

    public void StartDHKeyExchange() {
        try {
            long elapsetime = System.currentTimeMillis();
            this.keyExchange.SendPlainMessage();
            long Execution_Time1 = (System.currentTimeMillis() - elapsetime);
            System.out.println("---------------Execution Time1--------------------" + Execution_Time1);//60
            this.keyExchange.ReceiveServerCertificate();
            long Execution_Time2 = (System.currentTimeMillis() - Execution_Time1);
            System.out.println("---------------Execution Time2--------------------" + Execution_Time2);//1474378962584
            this.keyExchange.ResendCookieServer();
            long Execution_Time3 = (System.currentTimeMillis() - Execution_Time2);
            System.out.println("---------------Execution Time3--------------------" + Execution_Time3);//61
            this.keyExchange.SendPublicValue();
            long Execution_Time4 = (System.currentTimeMillis() - Execution_Time3);
            System.out.println("---------------Execution Time4--------------------" + Execution_Time4);//1474378962729
            this.keyExchange.ReceivePublicValue();
            long Execution_Time5 = (System.currentTimeMillis() - Execution_Time4);
            System.out.println("---------------Execution Time5--------------------" + Execution_Time5);//778
            this.keyExchange.SendCipherSuites();
            long Execution_Time6 = (System.currentTimeMillis() - Execution_Time5);
            System.out.println("---------------Execution Time6--------------------" + Execution_Time6);//778
            ciphersforUse = this.keyExchange.ReceiveCipherSuites();
            this.MessageExhange.setCiphersforUse(ciphersforUse);
            long Execution_Time7 = (System.currentTimeMillis() - Execution_Time6);
            System.out.println("---------------Execution Time7--------------------" + Execution_Time7);//778
            System.out.println("---------------Sum upTime------------------------ " + (System.currentTimeMillis() - elapsetime));
        } catch (IOException e) {
            e.printStackTrace();
            this.ConnectionClose();
            return;
        } catch (Exception e) {
            e.printStackTrace();
            this.ConnectionClose();
            return;
        }
    }

    public void SendSecureMessage(String Message) {
        this.MessageExhange.SendDHEncryptedMessage(Message);
    }

    public String ReceiveSecureMessage() {
        return this.MessageExhange.ReceiveDHEncryptedMessage();
    }

    public void ConnectionClose() {
        try {
            Session.getTransport().close();
        } catch (IOException ex) {
            Logger.getLogger(SessionHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
