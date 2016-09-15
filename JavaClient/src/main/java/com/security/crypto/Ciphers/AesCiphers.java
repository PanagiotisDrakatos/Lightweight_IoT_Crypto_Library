package com.security.crypto.Ciphers;


public interface AesCiphers {
    String AeS_Encrypt(String plaintext, String SecurePassword) throws Exception;

    String AeS_Decrypt(String encrypted, String SecurePassword) throws Exception;

}
