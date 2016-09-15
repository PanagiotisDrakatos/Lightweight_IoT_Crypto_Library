package com.security.crypto.KeyManager;

import com.security.crypto.Configuration.Properties;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class SymetricKeyGenerator extends GeneralKey {

    private String Base64SymetriKeyFormat;

    public SymetricKeyGenerator() {
        super(Type.DHSecretKey);
        this.Base64SymetriKeyFormat = null;
        GenerateClientKey();
        System.out.println(this.toString() + " created!");
    }

    private void GenerateClientKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[Properties.AesKeySizeLength];
        random.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, Properties.AES_ALGORITHM);
        String Base64StringKeyFormat = new String(Base64.encodeBase64(key.getEncoded()));
        this.Base64SymetriKeyFormat = Base64StringKeyFormat;
    }

    public String getBase64SymetricKeyFormat() {
        return Base64SymetriKeyFormat;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
