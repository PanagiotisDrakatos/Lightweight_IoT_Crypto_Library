package com.security.crypto.Handshake;

import com.security.crypto.Ciphers.AES.AesCBC;
import com.security.crypto.Ciphers.AES.AesECB;
import com.security.crypto.Configuration.CiphersForUse;
import com.security.crypto.Configuration.SupportedChipher;
import com.security.crypto.IOSocket.EstablishConnection;
import com.security.crypto.IOSocket.IOCallback;
import com.security.crypto.IOSocket.IOSynAck;
import com.security.crypto.KeyManager.KeyHandler;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

public class SessionHandler {

    private EstablishConnection Session = null;
    private KeyHandler keystore = null;
    private AesECB Ecb = null;
    private AesCBC Cbc = null;

    private IOSynAck keyExchange = null;
    private IOCallback MessageExhange = null;
    private CiphersForUse ciphersforUse = null;
    private SupportedChipher cName;

    public SessionHandler(String connection) {
        this.Session = new EstablishConnection(connection);
        this.keystore = new KeyHandler();
        this.keyExchange = new DHkeyExchange(this.Session.getTransport(), this.keystore);
    }


    public void StartDHKeyExchange() {
        try {
            long elapsetime = System.currentTimeMillis();
            this.keyExchange.SendPlainMessage();
            long Execution_Time1 = (System.currentTimeMillis());
            System.out.println("---------------Execution Time1--------------------" + (Execution_Time1 - elapsetime));//60

            long Execution_Time2 = (System.currentTimeMillis());
            this.keyExchange.ReceiveServerCertificate();
            System.out.println("---------------Execution Time2--------------------" + (System.currentTimeMillis() - Execution_Time2));//1474378962584

            long Execution_Time3 = (System.currentTimeMillis());
            this.keyExchange.ResendCookieServer();
            System.out.println("---------------Execution Time3--------------------" + (System.currentTimeMillis() - Execution_Time3));//61

            long Execution_Time4 = (System.currentTimeMillis());
            this.keyExchange.SendPublicValue();
            System.out.println("---------------Execution Time4--------------------" + (System.currentTimeMillis() - Execution_Time4));//1474378962729

            long Execution_Time5 = (System.currentTimeMillis());
            this.keyExchange.ReceivePublicValue();
            System.out.println("---------------Execution Time5--------------------" + (System.currentTimeMillis() - Execution_Time5));//77

            long Execution_Time6 = (System.currentTimeMillis());
            this.keyExchange.SendCipherSuites();
            System.out.println("---------------Execution Time6--------------------" + (System.currentTimeMillis() - Execution_Time6));//778

            long Execution_Time7 = (System.currentTimeMillis());
            ciphersforUse = this.keyExchange.ReceiveCipherSuites();
            System.out.println("---------------Execution Time7--------------------" + (Execution_Time7 - System.currentTimeMillis()));
            System.out.println("---------------Sum up Time------------------------ " + (System.currentTimeMillis() - elapsetime));//900 ms total

            this.MessageExhange = new IOMessageExhange(this.Session.getTransport(), this.keystore, ciphersforUse);
            StoreCipher();
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

    private void StoreCipher() {
        if (StringUtils.containsIgnoreCase(this.ciphersforUse.getCipherAlgorithm(), "ECB")) {
            this.cName = SupportedChipher.ECB;
            this.Ecb = new AesECB();
        } else {
            this.cName = SupportedChipher.CBC;
            this.Cbc = new AesCBC();
        }
    }

    public void SendSecureMessage(String Message) {
        try {
            switch (cName) {
                case ECB:
                    this.MessageExhange.SendDHEncryptedMessage(Message, this.Ecb);
                    break;
                case CBC:
                    this.MessageExhange.SendDHEncryptedMessage(Message, this.Cbc);
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String ReceiveSecureMessage() {
        try {
            switch (cName) {
                case ECB:
                    return this.MessageExhange.ReceiveDHEncryptedMessage(this.Ecb);

                case CBC:
                    return this.MessageExhange.ReceiveDHEncryptedMessage(this.Cbc);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void ConnectionClose() {
        try {
            Session.getTransport().close();
        } catch (IOException ex) {
            System.exit(1);
        }
    }

}
