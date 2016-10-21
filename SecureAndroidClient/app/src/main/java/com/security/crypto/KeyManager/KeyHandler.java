package com.security.crypto.KeyManager;

import android.content.Context;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.DHkeyExchange;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
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

import javax.crypto.spec.SecretKeySpec;

public class KeyHandler extends KeyManagerImp {

    private final DHCipherKey CipherKey;
    private final DHIntegrityKey IntegrityKey;
    private Context sContext;

    public KeyHandler(Context sContext) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.sContext = sContext;
        this.CipherKey = new DHCipherKey();
        this.IntegrityKey = new DHIntegrityKey();
        Key_Files();
    }

    public boolean Key_Files() {
        String PubPath = sContext.getFilesDir().getAbsolutePath() + "/" + Server_PUBLIC_KEY;
        String certPath = sContext.getFilesDir().getAbsolutePath() + "/" + Server_Certificate;
        File file = new File(PubPath);
        new File(certPath);
        return file.exists();
    }

    @Override
    public void SaveServerPublicKey() {
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        try {
            X509Certificate cert = this.loadCertificate();
            PublicKey key = cert.getPublicKey();
            byte[] keyBytes = key.getEncoded();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);

            fos = sContext.openFileOutput(Server_PUBLIC_KEY, Context.MODE_PRIVATE);
            oos = new ObjectOutputStream(new BufferedOutputStream(fos));
            oos.writeObject(x509EncodedKeySpec.getEncoded());
            oos.close();
            fos.close();
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
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            // Read Public Key.
            fis = sContext.openFileInput(Server_PUBLIC_KEY);
            ois = new ObjectInputStream(fis);
            byte[] encodedPublicKey = (byte[]) ois.readObject();
            //  Read Public Key.
            KeyFactory keyFactory = KeyFactory.getInstance(Properties.RSA_ALGORITHM);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    encodedPublicKey);
            publicKey = keyFactory.generatePublic(publicKeySpec);
            //return publicKey;
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public void SaveCertificate(String CertPemFormat) {
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        try {
            fos = sContext.openFileOutput(Server_Certificate, Context.MODE_PRIVATE);
            oos = new ObjectOutputStream(new BufferedOutputStream(fos));
            oos.writeObject(CertPemFormat.getBytes(Properties.CHAR_ENCODING));
            oos.close();
            fos.close();
            this.SaveServerPublicKey();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public X509Certificate loadCertificate() {
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            fis = sContext.openFileInput(Server_Certificate);
            ois = new ObjectInputStream(fis);
            byte[] Der_Encoded_Cert = (byte[]) ois.readObject();

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
        } catch (ClassNotFoundException e) {
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
