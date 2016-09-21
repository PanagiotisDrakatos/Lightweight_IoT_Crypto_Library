package com.security.crypto.KeyManager;


import com.security.crypto.Ciphers.AES.Digest;
import com.security.crypto.Configuration.Properties;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class DHCipherKey extends Keys {

    private SecretKeySpec CipherKey;
    private String SessionKey;

    public DHCipherKey() {
        super(Type.DHSecretKey);
        System.out.println(this.toString() + " created!");
    }

    public void GenerateCipherKey(String SessionKey) {
        try {
            this.SessionKey = SessionKey;
            byte[] keyBytes = Digest.Hash(this.SessionKey, Properties.HashingAlgorithm);
            byte[] CipherBytes16 = new byte[16];
            System.arraycopy(keyBytes, 0, CipherBytes16, 0, 16);
            this.CipherKey = new SecretKeySpec(CipherBytes16, Properties.AES_PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String RetriveSessionKey() {
        return this.SessionKey;
    }

    public SecretKeySpec getCipherKey() {
        return CipherKey;
    }

    @Override
    public String toString() {
        return super.toString();
    }

}
