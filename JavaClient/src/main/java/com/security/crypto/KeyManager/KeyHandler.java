package com.security.crypto.KeyManager;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.DHkeyExchange;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
    public void saveServerPublicKey(Certificate cert) {
        try {

            if (cert instanceof X509Certificate) {
                X509Certificate x = (X509Certificate) cert;
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(x.getEncoded());
                FileOutputStream Fos = new FileOutputStream(Server_PUBLIC_KEY);
                Fos.write(x509EncodedKeySpec.getEncoded());
                Fos.close();
            } else
                throw new CertificateException("Not valid Cetificate");


        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(DHkeyExchange.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException e) {
            e.printStackTrace();
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


    @Override
    public DHSecretKey/**/ loadRemoteSecretKey() {
        return this.SecretKey; //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public SymetricKeyGenerator loadRemoteSymetricKey() {
        return this.SymetricKey;
    }


    }
