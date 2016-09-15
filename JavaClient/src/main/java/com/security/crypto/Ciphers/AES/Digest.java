package com.security.crypto.Ciphers.AES;


import com.security.crypto.Configuration.Properties;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Digest {

    public static byte[] Digest(String key, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(key.getBytes(Properties.CHAR_ENCODING));
        byte[] keyBytes = md.digest();
        return keyBytes;
    }
}
