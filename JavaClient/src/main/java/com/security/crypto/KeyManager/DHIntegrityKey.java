package com.security.crypto.KeyManager;


import com.security.crypto.Configuration.Properties;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;

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
            byte[] keyBytes = SessionKey.getBytes(Properties.CHAR_ENCODING);
            // System.out.println("length is "+keyBytes.length);
            byte[] keyBytes16 = new byte[16];
            //Math.min(bytes.length/2,16),Math.min(bytes.length,32)
            System.arraycopy(keyBytes, Math.min(keyBytes.length / 2, 16), keyBytes16, 0, Math.min(keyBytes.length, 16));
            this.integrityKey = new SecretKeySpec(new String(keyBytes16).getBytes(Properties.CHAR_ENCODING), Properties.AES_PROVIDER);

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
