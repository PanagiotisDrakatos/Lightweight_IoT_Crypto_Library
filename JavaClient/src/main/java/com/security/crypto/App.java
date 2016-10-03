package com.security.crypto;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.SessionHandler;


/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {

        SessionHandler session = new SessionHandler(Properties.PlainTextConnection);
        String Receive = null;
        session.StartDHKeyExchange();
        session.SendSecureMessage("hello Server 1");
        Receive = session.ReceiveSecureMessage();
        System.out.println(Receive);
        session.SendSecureMessage("hello Server 2");
        Receive = session.ReceiveSecureMessage();
        System.out.println(Receive);
        session.ConnectionClose();
    }


}
