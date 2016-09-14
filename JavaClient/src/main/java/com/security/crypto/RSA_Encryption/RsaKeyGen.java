package com.security.crypto.RSA_Encryption;


import com.security.crypto.Configuration.Properties;
import com.security.crypto.KeyManager.KeyManagerImp;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RsaKeyGen {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private final KeyManagerImp keystore;

    public RsaKeyGen(KeyManagerImp keystore) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.keystore = keystore;
        boolean result = (this.keystore.Key_Files()) && GenerateKeys();
    }

    private boolean GenerateKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Properties.RSA_ALGORITHM, Properties.RSA_Provider);
        keyPairGenerator.initialize(Properties.RSA_KEYSIZE); //2048 used for normal securities
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        PullingParametrs();
        return true;
    }

    private void PullingParametrs() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance(Properties.RSA_ALGORITHM);
        RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        this.keystore.saveClientKeyPair(KeyManagerImp.Client_PUBLIC_KEY, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
        this.keystore.saveClientKeyPair(KeyManagerImp.Client_PRIVATE_KEY, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());
    }

}
