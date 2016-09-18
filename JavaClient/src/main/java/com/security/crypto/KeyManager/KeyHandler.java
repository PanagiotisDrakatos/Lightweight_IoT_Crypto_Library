package com.security.crypto.KeyManager;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.DHkeyExchange;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyHandler extends KeyManagerImp {

    private final SymetricKeyGenerator SymetricKey;
    private final DHSecretKey SecretKey;


    public KeyHandler() {
        this.SecretKey = new DHSecretKey();
        this.SymetricKey = new SymetricKeyGenerator();
    }

    @Override
    public void saveServerPublicKey() {
        try {
            PublicKey key = this.loadCertificate().getPublicKey();
            byte[] keyBytes = key.getEncoded();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            FileOutputStream Fos = new FileOutputStream(KeyManagerImp.Server_PUBLIC_KEY);
            Fos.write(x509EncodedKeySpec.getEncoded());
            Fos.close();
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void saveSecretKey(String keyStringFormat) {
        this.SecretKey.setSessionKey(keyStringFormat);
    }

    /**
     * @return
     */
    @Override
    public PublicKey loadRemoteServerPublicKey() {
        PublicKey publicKey = null;
        FileInputStream fis;
        try {
            // Read Public Key.
            File filePublicKey = new File(Server_PUBLIC_KEY);
            fis = new FileInputStream(Server_PUBLIC_KEY);
            byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
            fis.read(encodedPublicKey);
            fis.close();
            //  Read Public Key.
            KeyFactory keyFactory = KeyFactory.getInstance(Properties.RSA_ALGORITHM);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    encodedPublicKey);
            publicKey = keyFactory.generatePublic(publicKeySpec);
            //return publicKey;
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        }
        return publicKey;
    }

    public void saveCertificate(String CertPemFormat) {
        try {
            FileOutputStream Fos = new FileOutputStream(KeyManagerImp.Server_PUBLIC_KEY);
            Fos.write(CertPemFormat.getBytes(Properties.CHAR_ENCODING));
            Fos.close();
            this.saveServerPublicKey();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public X509Certificate loadCertificate() {
        FileInputStream is = null;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            is = new FileInputStream(new File(Server_Certificate));
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            return cer;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public DHSecretKey/**/ loadRemoteSecretKey() {
        return this.SecretKey; //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public SymetricKeyGenerator loadRemoteSymetricKey() {
        return this.SymetricKey;
    }


}
