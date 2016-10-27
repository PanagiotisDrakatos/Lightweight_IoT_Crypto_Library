package com.security.crypto;

/**
 * Hello world!
 */
public class App {
    public enum Command {
        PlainTextConnection, SslTlsV2,
    }

    public static void main(String[] args) throws Exception {

        int LoopValue = 100;
        //To run this code Make sure you open PlainConnection.js in order to connect to the  server
        PerfomanceTime per = new PerfomanceTime(LoopValue, Command.PlainTextConnection);//set counter for LoopValue & set Property PlainTextConnection
        per.Set_CryptoDevice_Experiment();//Save  time in ms in a HashMap for each Connection
        per.WriteData();//write HashMap data to excel*/

        //-------------------------------------------------------------------//

        //To run this code Make sure you open SslTlsV2.js in order to connect to the node.js server
        PerfomanceTime ssl = new PerfomanceTime(LoopValue, Command.SslTlsV2);//set counter for LoopValue & set Property SslTlsV2
        ssl.Set_SSl_Experiment();//Update Excel data with ssl time
    }


}
