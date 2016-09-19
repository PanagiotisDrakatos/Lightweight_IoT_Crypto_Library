package com.security.crypto.Configuration;

public abstract class Properties {

    //socket properties

    public static final String host = "192.168.1.66";
    public static final int portNumber = 1337;
    public static final String PlainTextConnection = "PlainTextConnection";
    public static final String SslTlsV2 = "SslTlsV2";


    public static final String SYN = "ClientHello";
    public static final String SYN_ACK = "ServerHello";
    public static final String Replay = "Resend";


    //encryption properties  
    //for more info check https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
    //g^x mod p 
    //However, its very unlikely that anyone else listening on the channel 
    //can calculate the key, since the calculation of discrete logarithms under 
    //field arithmetic is very hard (see Galois Fields)
    //Prime numbers machine generator 
    public static final String exponent = "95632573769194905177488615436919317766582673020891665265323677789504596581977";
    public static final String modulus = "81554351438297688582888558141846154981885664956959015742153749206820791432251";

    public static final String AES_PROVIDER = "AES";
    public static final String AES_ALGORITHM = "AES/ECB/PKCS7Padding";

    //Rsa needed
    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_CRYPTO_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String RSA_Provider = "BC";

    //store_keys
    //Encodes values
    public static final String CHAR_ENCODING = "UTF-8";
    public static final String HashingAlgorithm = "md5";

    //keysizes-length
    public static final int AesKeySizeLength = 64;
    public static final int RSA_KEYSIZE = 2048;

    //HmacAlgProvider hash Function
    public static final String HmacAlgProv = "HmacSHA256";
    //Rsa Integrity Signature
    public static final String Signature = "SHA256withRSA";

}
