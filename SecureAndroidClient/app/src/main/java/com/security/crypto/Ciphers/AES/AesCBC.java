package com.security.crypto.Ciphers.AES;


import com.security.crypto.Configuration.Properties;

import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCBC implements AesCiphers {
    private static byte[] ivBytes = new byte[]{0x15, 0x14, 0x13, 0x12, 0x11,
            0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    private IvParameterSpec ivSpec;

    public AesCBC() {
        SecureRandom random = new SecureRandom();
        byte[] randBytes = new byte[16];
        random.nextBytes(randBytes);
        ivSpec = new IvParameterSpec(randBytes);
    }

    public String AeS_Encrypt(String plaintext, String key) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // convert plain text to bytes
        byte[] plainBytes = plaintext.getBytes(Properties.CHAR_ENCODING);

        Cipher cipher = Cipher.getInstance(Properties.AES_CBC);
        byte[] keybytes = Digest.Hash(key, Properties.MD5);
        SecretKeySpec sky = new SecretKeySpec(keybytes, Properties.AES_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, sky, new IvParameterSpec(ivBytes));
        // encrypt
        byte[] encrypted = cipher.doFinal(plainBytes);
        String encryptedString = new String(Base64.encodeBase64(encrypted));

        return encryptedString;

    }

    public String AeS_Decrypt(String encrypted, String key) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // convert plain text to bytes
        byte[] plainBytes = Base64.decodeBase64(encrypted.getBytes(Properties.CHAR_ENCODING));
        byte[] keybytes = Digest.Hash(key, Properties.MD5);
        SecretKeySpec sky = new SecretKeySpec(keybytes, Properties.AES_PROVIDER);
        Cipher cipher = Cipher.getInstance(Properties.AES_CBC);
        cipher.init(Cipher.DECRYPT_MODE, sky, new IvParameterSpec(ivBytes));

        byte[] decrypted = cipher.doFinal(plainBytes);
        return new String(decrypted, Properties.CHAR_ENCODING);
    }
}