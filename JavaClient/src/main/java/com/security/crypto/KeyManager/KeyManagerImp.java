package com.security.crypto.KeyManager;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyManagerImp {

    String exponent = "95632573769194905177488615436919317766582673020891665265323677789504596581977";
    String modulus = "81554351438297688582888558141846154981885664956959015742153749206820791432251";

    //unfortunately this works only for Windows os
    String Server_PUBLIC_KEY = System.getProperty("user.dir") + "\\Server\\Public.key";
    String Client_PUBLIC_KEY = System.getProperty("user.dir") + "\\Client\\Public.key";
    String Client_PRIVATE_KEY = System.getProperty("user.dir") + "\\Client\\Private.key";

    void saveServerPublicKey(String pubKey);

    void saveClientKeyPair(String fileName, BigInteger modules, BigInteger exponent);

    void saveSecretKey(String keyStringFormat);

    PublicKey loadRemoteServerPublicKey();

    PublicKey loadClientPublicKey();

    String loadStringFormatClientPublicKey();

    PrivateKey loadClientPrivateKey();

    DHSecretKey loadRemoteSecretKey();

    SymetricKeyGenerator loadRemoteSymetricKey();

    boolean Key_Files();

}
