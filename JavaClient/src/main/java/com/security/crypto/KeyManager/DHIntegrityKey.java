package com.security.crypto.KeyManager;


import com.security.crypto.Ciphers.AES.Digest;
import com.security.crypto.Configuration.Properties;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class DHIntegrityKey extends Keys {

    private SecretKeySpec integrityKey;
    private String SessionKey;

    public DHIntegrityKey() {
        super(Type.DHIntegrityKey);
        System.out.println(this.toString() + " created!");
    }

    public void GenerateIntegrityKey(String SessionKey) {
        try {
            this.SessionKey = SessionKey;
            byte[] keyBytes = Digest.Hash(this.SessionKey, Properties.HashingAlgorithm);
            byte[] IntegrityBytes16 = new byte[16];
            System.arraycopy(keyBytes, 16, IntegrityBytes16, 0, 16);
            this.integrityKey = new SecretKeySpec(IntegrityBytes16, Properties.AES_PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String RetriveSessionKey() {
        return this.SessionKey;
    }

    public SecretKeySpec getIntegrityKey() {
        return integrityKey;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
