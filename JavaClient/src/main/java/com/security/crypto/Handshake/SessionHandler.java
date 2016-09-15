package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.RSA.RsaKeyGen;
import com.security.crypto.IOSocket.EstablishConnection;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOSynAck;
import com.security.crypto.KeyManager.KeyHandler;
import com.security.crypto.KeyManager.KeyManagerImp;

import java.awt.*;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SessionHandler {

    private EstablishConnection Session = null;
    private KeyManagerImp keystore = null;

    private IOSynAck keyExchange = null;
    private IOCallback MessageExhange = null;

    private Timer timer;
    private Toolkit toolkit;

    public SessionHandler(String connection) {
        try {
            this.Session = new EstablishConnection(connection);
            this.keystore = new KeyHandler();
            RsaKeyGen rsaKeyGen = new RsaKeyGen(this.keystore);
            this.keyExchange = new DHkeyExchange(this.Session.getTransport(), this.keystore);
            this.MessageExhange = new IOMessageExhange(this.Session.getTransport(), this.keystore);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            Logger.getLogger(SessionHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public SessionHandler(String connection, int timeout) {
        try {
            this.Session = new EstablishConnection(connection, timeout);
            this.keystore = new KeyHandler();
            RsaKeyGen rsaKeyGen = new RsaKeyGen(this.keystore);
            this.keyExchange = new DHkeyExchange(this.Session.getTransport(), this.keystore);
            this.MessageExhange = new IOMessageExhange(this.Session.getTransport(), this.keystore);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            Logger.getLogger(SessionHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void StartDHKeyExchange() {
        this.keyExchange.SendClientPublicKey();
        this.keyExchange.ReceiveServerPublicKey();
        this.keyExchange.SendPrimeNumber();
        this.keyExchange.EndDHsession();
        System.out.println("---------------DHkeys Sucessfuly Changed--------------------");
    }

    public void TimerRenew(int seconds) {
        toolkit = Toolkit.getDefaultToolkit();
        timer = new Timer();
        timer.schedule(new RemindTask(), seconds * 1000);
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

    class RemindTask extends TimerTask {

        @Override
        public void run() {
            System.out.println("Time's up need Reset!");
            toolkit.beep();
            System.exit(0); //Stops the AWT thread (and everything else)
        }
    }

}
