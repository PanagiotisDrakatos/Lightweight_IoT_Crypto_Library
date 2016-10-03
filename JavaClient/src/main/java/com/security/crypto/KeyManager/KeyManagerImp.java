package com.security.crypto.KeyManager;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public abstract class KeyManagerImp {


    //unfortunately this works only for Windows os
    public String currentpath = System.getProperty("user.dir") + "\\ClientStore\\";
    public String Server_PUBLIC_KEY = currentpath + "Public.key";
    public String Server_Certificate = currentpath + "Certificate.pem";

    public abstract void SaveServerPublicKey();

    public abstract void SaveCertificate(String CertPemFormat);

    public abstract void ProduceCipherKey(String SessionResult);

    public abstract void ProduceIntegrityKey(String SessionResult);

    public abstract PublicKey loadRemoteServerPublicKey();

    public abstract X509Certificate loadCertificate() throws IOException;

    public abstract String loadRemoteCipherKey();

    public abstract SecretKeySpec loadRemoteIntegrityKey();


}
