package com.security.crypto.Ciphers;


import javax.crypto.spec.SecretKeySpec;

public interface AesCiphers {
    String AeS_Encrypt(String plaintext, SecretKeySpec ChiperKey) throws Exception;

    String AeS_Decrypt(String encrypted, SecretKeySpec ChiperKey) throws Exception;

}
