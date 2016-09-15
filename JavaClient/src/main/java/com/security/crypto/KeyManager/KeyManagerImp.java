package com.security.crypto.KeyManager;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class KeyManagerImp {

    public static final String exponent = "95632573769194905177488615436919317766582673020891665265323677789504596581977";
    public static final String modulus = "81554351438297688582888558141846154981885664956959015742153749206820791432251";

    //unfortunately this works only for Windows os
    public static final String Server_PUBLIC_KEY = System.getProperty("user.dir") + "\\Server\\Public.key";
    public static final String Client_PUBLIC_KEY = System.getProperty("user.dir") + "\\Client\\Public.key";
    public static final String Client_PRIVATE_KEY = System.getProperty("user.dir") + "\\Client\\Private.key";
    public static final String StringToReplace = "(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)";

    public abstract void saveServerPublicKey(String pubKey);

    public abstract void saveClientKeyPair(String fileName, BigInteger modules, BigInteger exponent);

    public abstract void saveSecretKey(String keyStringFormat);

    public abstract PublicKey loadRemoteServerPublicKey();

    public abstract PublicKey loadClientPublicKey();

    public abstract String loadStringFormatClientPublicKey();

    public abstract PrivateKey loadClientPrivateKey();

    public abstract DHSecretKey loadRemoteSecretKey();

    public abstract SymetricKeyGenerator loadRemoteSymetricKey();

    public abstract boolean Key_Files();

}
