package com.security.crypto.KeyManager;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.spec.SecretKeySpec;

public abstract class KeyManagerImp {


    //unfortunately this works only for Windows os
    public String Server_PUBLIC_KEY = "Public.key";
    public String Server_Certificate = "Certificate.pem";

    public abstract void SaveServerPublicKey();

    public abstract void SaveCertificate(String CertPemFormat);

    public abstract void ProduceCipherKey(String SessionResult);

    public abstract void ProduceIntegrityKey(String SessionResult);

    public abstract PublicKey loadRemoteServerPublicKey();

    public abstract X509Certificate loadCertificate() throws IOException;

    public abstract String loadRemoteCipherKey();

    public abstract SecretKeySpec loadRemoteIntegrityKey();


}
