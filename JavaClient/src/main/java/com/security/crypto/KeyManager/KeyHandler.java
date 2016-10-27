package com.security.crypto.KeyManager;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.DHkeyExchange;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyHandler extends KeyManagerImp {

    private final DHCipherKey CipherKey;
    private final DHIntegrityKey IntegrityKey;


    public KeyHandler() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.CipherKey = new DHCipherKey();
        this.IntegrityKey = new DHIntegrityKey();
        File f = new File(currentpath);
        if (!f.exists())
            f.mkdir();
    }

    @Override
    public void SaveServerPublicKey() {
        try {
            X509Certificate cert = this.loadCertificate();
            PublicKey key = cert.getPublicKey();
            //System.out.println(key);
            byte[] keyBytes = key.getEncoded();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            FileOutputStream Fos = new FileOutputStream(new File(Server_PUBLIC_KEY));
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
    public void ProduceCipherKey(String SessionResult) {

        this.CipherKey.GenerateCipherKey(SessionResult);
    }

    @Override
    public void ProduceIntegrityKey(String SessionResult) {

        this.IntegrityKey.GenerateIntegrityKey(SessionResult);
    }


    @Override
    public PublicKey loadRemoteServerPublicKey() {
        PublicKey publicKey = null;
        FileInputStream fis;
        try {
            // Read Public Key.
            File filePublicKey = new File(Server_PUBLIC_KEY);
            fis = new FileInputStream(filePublicKey);
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

    public void SaveCertificate(String CertPemFormat) {
        try {
            FileOutputStream Fos = new FileOutputStream(new File(Server_Certificate));
            Fos.write(CertPemFormat.getBytes(Properties.CHAR_ENCODING));
            Fos.close();
            this.SaveServerPublicKey();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public X509Certificate loadCertificate() {
        FileInputStream fis = null;
        try {
            File filecert = new File(Server_Certificate);
            fis = new FileInputStream(filecert);
            byte[] Der_Encoded_Cert = new byte[(int) filecert.length()];
            fis.read(Der_Encoded_Cert);

            byte[] data = Base64.decodeBase64(Der_Encoded_Cert);
            ByteArrayInputStream inStream = new ByteArrayInputStream(data);
            ASN1InputStream derin = new ASN1InputStream(inStream);
            ASN1Primitive certInfo = derin.readObject();
            ASN1Sequence seq = ASN1Sequence.getInstance(certInfo);

            fis.close();
            return new X509CertificateObject(Certificate.getInstance(seq));

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String loadRemoteCipherKey() {
        return this.CipherKey.getCipherKey();
    }

    @Override
    public SecretKeySpec loadRemoteIntegrityKey() {

        return this.IntegrityKey.getIntegrityKey();
    }


}
