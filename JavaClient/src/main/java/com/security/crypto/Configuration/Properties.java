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
    public static final String exponent = "67849492012064603525502413864581601255843190582896059031333969517102908698009";
    public static final String modulus = "2488305068742644273557582289228577695008613947504239231451478997448862967615054559158646690894413368612518781574622331108225213890389508634163395377693";

    public static final String AES_PROVIDER = "AES";
    public static final String AES_ECB = "AES/ECB/PKCS7Padding";
    public static final String AES_CBC = "AES/CBC/PKCS7Padding";

    public static final String MD5 = "md5";
    public static final String sha1 = "SHA-1";
    public static final String SHA_256 = "SHA-256";
    public static final String MACSHA_256 = "HmacSHA256";

    //Rsa needed
    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_CRYPTO_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String RSA_Provider = "BC";

    //store_keys
    //Encodes values
    public static final String CHAR_ENCODING = "UTF-8";


    //keysizes-length
    public static final int AesKeySizeLength = 64;
    public static final int RSA_KEYSIZE = 2048;

    //HmacAlgProvider hash Function
    public static final String HmacAlgProv = "HmacSHA256";
    //Rsa Integrity Signature
    public static final String Signature = "SHA256withRSA";

}
