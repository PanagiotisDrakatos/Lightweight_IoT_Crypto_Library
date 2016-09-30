package com.security.crypto.Ciphers.RSA;

import com.security.crypto.Configuration.Properties;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSA_PKCS1 implements RsaCiphers {

    public String RsaEncrypt(PublicKey pubKey, String plainText) throws Exception {
        byte[] plainBytes = plainText.getBytes(Properties.CHAR_ENCODING);
        Cipher cipher = Cipher.getInstance(Properties.RSA_CRYPTO_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted = cipher.doFinal(plainBytes);
        String encryptedString = new String(Base64.encodeBase64(encrypted));

        return encryptedString;
    }

    public String RsaDecrypt(PrivateKey privateKey, String EncryptedText) throws Exception {
        byte[] plainBytes = Base64.decodeBase64(EncryptedText.getBytes(Properties.CHAR_ENCODING));
        Cipher cipher = Cipher.getInstance(Properties.RSA_CRYPTO_ALGORITHM, Properties.RSA_Provider);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypteed = cipher.doFinal(plainBytes);
        String DecryptedString = new String(decrypteed, "UTF-8");

        return DecryptedString;
    }
}
