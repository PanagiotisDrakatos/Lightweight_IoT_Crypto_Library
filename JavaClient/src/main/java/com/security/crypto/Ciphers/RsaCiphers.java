package com.security.crypto.Ciphers;

import java.security.PrivateKey;
import java.security.PublicKey;


public interface RsaCiphers {
    String RsaEncrypt(PublicKey pubKey, String plainText) throws Exception;

    String RsaDecrypt(PrivateKey privateKey, String EncryptedText) throws Exception;
}
