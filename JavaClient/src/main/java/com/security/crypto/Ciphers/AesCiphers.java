package com.security.crypto.Ciphers;


public interface AesCiphers {
    String AeS_Encrypt(String plaintext, String Key) throws Exception;

    String AeS_Decrypt(String encrypted, String Key) throws Exception;

}
