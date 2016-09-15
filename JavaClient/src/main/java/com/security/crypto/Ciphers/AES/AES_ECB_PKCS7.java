package com.security.crypto.Ciphers.AES;

import com.security.crypto.Ciphers.AesCiphers;
import com.security.crypto.Configuration.Properties;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class AES_ECB_PKCS7 implements AesCiphers {

    public String AeS_Encrypt(String plaintext, String SecurePassword) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] keyBytes = Digest.Digest(SecurePassword, Properties.HashingAlgorithm);
        // convert plain text to bytes
        byte[] plainBytes = plaintext.getBytes(Properties.CHAR_ENCODING);

        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, Properties.AES_PROVIDER);

        Cipher cipher = Cipher.getInstance(Properties.AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        // encrypt
        byte[] encrypted = cipher.doFinal(plainBytes);
        String encryptedString = new String(Base64.encodeBase64(encrypted));

        return encryptedString;

    }

    public String AeS_Decrypt(String encrypted, String SecurePassword) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] keyBytes = Digest.Digest(SecurePassword, Properties.HashingAlgorithm);
        // convert plain text to bytes
        byte[] plainBytes = Base64.decodeBase64(encrypted.getBytes(Properties.CHAR_ENCODING));
        SecretKeySpec skey = new SecretKeySpec(keyBytes, Properties.AES_PROVIDER);
        Cipher cipher = Cipher.getInstance(Properties.AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skey);

        byte[] decrypted = cipher.doFinal(plainBytes);
        return new String(decrypted, Properties.CHAR_ENCODING);
    }
}
