package com.security.crypto.Ciphers.AES;

import com.security.crypto.Ciphers.AesCiphers;
import com.security.crypto.Configuration.Properties;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class AesECB implements AesCiphers {


    public String AeS_Encrypt(String plaintext, String Key) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // convert plain text to bytes
        byte[] plainBytes = plaintext.getBytes(Properties.CHAR_ENCODING);
        Cipher cipher = Cipher.getInstance(Properties.AES_ECB);
        byte[] keybytes = Digest.Hash(Key, Properties.MD5);
        SecretKeySpec sky = new SecretKeySpec(keybytes, Properties.AES_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, sky);
        // encrypt
        byte[] encrypted = cipher.doFinal(plainBytes);
        String encryptedString = new String(Base64.encodeBase64(encrypted));

        return encryptedString;

    }

    public String AeS_Decrypt(String encrypted, String Key) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // convert plain text to bytes
        byte[] plainBytes = Base64.decodeBase64(encrypted.getBytes(Properties.CHAR_ENCODING));
        byte[] keybytes = Digest.Hash(Key, Properties.MD5);
        SecretKeySpec sky = new SecretKeySpec(keybytes, Properties.AES_PROVIDER);
        Cipher cipher = Cipher.getInstance(Properties.AES_ECB);
        cipher.init(Cipher.DECRYPT_MODE, sky);

        byte[] decrypted = cipher.doFinal(plainBytes);
        return new String(decrypted, Properties.CHAR_ENCODING);
    }
}
