package com.security.crypto;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.SessionHandler;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        SessionHandler session = new SessionHandler(Properties.PlainTextConnection);
        session.StartDHKeyExchange();
        session.SendSecureMessage("hello Server 1");
        String Receive = session.ReceiveSecureMessage();
        System.out.println(Receive+ "1");
        session.SendSecureMessage("hello Server2");
        Receive = session.ReceiveSecureMessage();
        System.out.println(Receive + "2");
        session.ConnectionClose();
    }
}
