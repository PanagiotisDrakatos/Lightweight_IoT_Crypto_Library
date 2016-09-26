package com.security.crypto.KeyManager;


import com.security.crypto.Configuration.Properties;

import java.io.UnsupportedEncodingException;

public class DHCipherKey extends Keys {

    private String CipherKey;
    private String SessionKey;

    public DHCipherKey() {
        super(Type.DHSecretKey);
        System.out.println(this.toString() + " created!");
    }

    public void GenerateCipherKey(String SessionKey) {
        try {
            this.SessionKey = SessionKey;
            byte[] keyBytes = SessionKey.getBytes(Properties.CHAR_ENCODING);
            byte[] keyBytes16 = new byte[16];
            System.arraycopy(keyBytes, 0, keyBytes16, 0, Math.min(keyBytes.length / 2, 16));
            // byte[] hash = Digest.Hash(new String(keyBytes16), Properties.MD5);
            // this.CipherKey = new SecretKeySpec(hash, Properties.AES_PROVIDER);
            this.CipherKey = new String(keyBytes16);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String RetriveSessionKey() {
        return this.SessionKey;
    }

    public String getCipherKey() {
        return CipherKey;
    }

    @Override
    public String toString() {
        return super.toString();
    }

}
