package com.security.crypto.KeyManager;

import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public abstract class KeyManagerImp {


    public static final String exponent = "67849492012064603525502413864581601255843190582896059031333969517102908698009";
    public static final String modulus = "106953682714365274028621778978603013937497125686512166290051415904041709752171";
    //unfortunately this works only for Windows os
    public String currentpath = System.getProperty("user.dir") + "\\ClientStore\\";
    public String Server_PUBLIC_KEY = currentpath + "Public.key";
    public String Server_Certificate = currentpath + "Certificate.pem";

    public abstract void SaveServerPublicKey();

    public abstract void SaveCertificate(String CertPemFormat);

    public abstract void ProduceCipherKey(String SessionResult);

    public abstract void ProduceIntegrityKey(String SessionResult);

    public abstract PublicKey loadRemoteServerPublicKey();

    public abstract X509Certificate loadCertificate();

    public abstract SecretKeySpec loadRemoteCipherKey();

    public abstract SecretKeySpec loadRemoteIntegrityKey();


}
