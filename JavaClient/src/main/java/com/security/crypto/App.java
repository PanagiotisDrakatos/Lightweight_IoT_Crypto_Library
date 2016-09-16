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
        /*SessionHandler session = new SessionHandler(Properties.PlainTextConnection);
        session.TimerRenew(1);   //Users can intialize the time witch the keys will be reproduced so it will be impossible for NSA break keys
        session.StartDHKeyExchange();
        //or
        //session.StartDHKeyExchange(23000);//socket timeout
        session.SendSecureMessage("hello Server 1");
        // Thread.sleep(10000);
        String Receive = session.ReceiveSecureMessage();//Server says hello client
        System.out.println(Receive+ "1");
        // session.AutoRenew will be called every 10 minutes if User will not set Renew GeneralKey so it will be impossible for NSA break keys
        // session.SendSecureMessage("whats up Server");
        //String Receive=session.ReceiveSecureMessage();//i am fine thnx
        session.SendSecureMessage("hello Server2");
        // session.TimerRenew(50000);//Users can intialize the time witch the keys will be reproduced so it will be impossible for NSA break keys
        Receive = session.ReceiveSecureMessage();//Server says hello client
        System.out.println(Receive + "2");
        session.ConnectionClose();*/
    }
}
