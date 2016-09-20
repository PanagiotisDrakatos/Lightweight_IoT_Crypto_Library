package com.security.crypto.KeyManager;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public abstract class KeyManagerImp {

    public static final String exponent = "95632573769194905177488615436919317766582673020891665265323677789504596581977";
    public static final String modulus = "81554351438297688582888558141846154981885664956959015742153749206820791432251";

    //unfortunately this works only for Windows os
    public String currentpath = System.getProperty("user.dir") + "\\ClientStore\\";
    public String Server_PUBLIC_KEY = currentpath + "Public.key";
    public String Server_Certificate = currentpath + "Certificate.pem";

    public abstract void saveServerPublicKey();

    public abstract void saveCertificate(String CertPemFormat);

    public abstract void saveSecretKey(String keyStringFormat);

    public abstract PublicKey loadRemoteServerPublicKey();

    public abstract DHSecretKey loadRemoteSecretKey();

    public abstract SymetricKeyGenerator loadRemoteSymetricKey();

    public abstract X509Certificate loadCertificate();


}
