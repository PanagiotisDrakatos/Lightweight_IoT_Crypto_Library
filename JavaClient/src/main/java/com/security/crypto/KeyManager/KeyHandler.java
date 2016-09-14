package com.security.crypto.KeyManager;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.DHkeyExchange;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyHandler implements KeyManagerImp {

    private final SymetricKeyGenerator SymetricKey;
    private final DHSecretKey SecretKey;
    private static final String StringToReplace = "(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)";

    public KeyHandler() {
        this.SecretKey = new DHSecretKey();
        this.SymetricKey = new SymetricKeyGenerator();
    }

    /**
     * @param pubKey
     */
    @Override
    public void saveServerPublicKey(String pubKey) {
        try {
            // 
            pubKey = pubKey.replaceAll(StringToReplace, "");
            byte[] keyBytes = Base64.decodeBase64(pubKey.getBytes(Properties.CHAR_ENCODING));
            // Store Public Key.
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
            File filePublicKey = new File(KeyManagerImp.Server_PUBLIC_KEY);
            fis = new FileInputStream(KeyManagerImp.Server_PUBLIC_KEY);
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

    /**
     * @return
     */
    @Override
    public DHSecretKey/**/ loadRemoteSecretKey() {
        return this.SecretKey; //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public SymetricKeyGenerator loadRemoteSymetricKey() {
        return this.SymetricKey;
    }

    @Override
    public PublicKey loadClientPublicKey() {
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            fis = new FileInputStream(new File(KeyManagerImp.Client_PUBLIC_KEY));
            ois = new ObjectInputStream(fis);

            BigInteger mod = (BigInteger) ois.readObject();
            BigInteger expon = (BigInteger) ois.readObject();

            //Get Public Key
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(mod, expon);
            KeyFactory fact = KeyFactory.getInstance(Properties.RSA_ALGORITHM);
            PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);

            return publicKey;

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
        } finally {
            if (ois != null) {
                try {
                    ois.close();
                    if (fis != null) {
                        fis.close();
                    }
                } catch (IOException ex) {
                    Logger.getLogger(KeyHandler.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return null;
    }

    @Override
    public PrivateKey loadClientPrivateKey() {
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            fis = new FileInputStream(new File(KeyManagerImp.Client_PRIVATE_KEY));
            ois = new ObjectInputStream(fis);

            BigInteger mod = (BigInteger) ois.readObject();
            BigInteger exp = (BigInteger) ois.readObject();

            //Get Private Key
            RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(mod, exp);
            KeyFactory fact = KeyFactory.getInstance(Properties.RSA_ALGORITHM);
            PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);

            return privateKey;

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
        } finally {
            if (ois != null) {
                try {
                    ois.close();
                    if (fis != null) {
                        fis.close();
                    }
                } catch (IOException ex) {
                    Logger.getLogger(KeyHandler.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return null;
    }

    @Override
    public void saveClientKeyPair(String fileName, BigInteger modules, BigInteger exponent) {
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;

        try {
            //System.out.println("Generating " + fileName + "...");
            fos = new FileOutputStream(fileName);
            oos = new ObjectOutputStream(new BufferedOutputStream(fos));

            oos.writeObject(modules);
            oos.writeObject(exponent);
            // System.out.println(fileName + " generated successfully");
        } catch (Exception e) {
        } finally {
            if (oos != null) {
                try {
                    oos.close();

                    if (fos != null) {
                        fos.close();
                    }
                } catch (IOException ex) {
                    Logger.getLogger(KeyHandler.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    /**
     * @return
     */
    @Override
    public boolean Key_Files() {

        File privateKey = new File(KeyManagerImp.Client_PRIVATE_KEY);
        File publicKey = new File(KeyManagerImp.Client_PUBLIC_KEY);

        return !(privateKey.exists() && publicKey.exists());
    }

    @Override
    public String loadStringFormatClientPublicKey() {
        try {
            byte[] encoded = loadClientPublicKey().getEncoded();
            ASN1Sequence dsds = ASN1Sequence.getInstance(encoded);
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));
            byte[] otherEncoded = Base64.encodeBase64(subjectPublicKeyInfo.getPublicKey().getEncoded());
            String publikey = new String(otherEncoded);
            return publikey;
        } catch (IOException ex) {
            Logger.getLogger(KeyHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
