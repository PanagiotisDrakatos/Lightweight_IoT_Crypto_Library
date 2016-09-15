package com.security.crypto.Ciphers.RSA;

import com.security.crypto.Configuration.Properties;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.security.*;

public class Fingerprint {

    public static String SignData(String encrypted, PrivateKey privatekey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, IOException {

        Signature mySign = Signature.getInstance(Properties.Signature);
        mySign.initSign(privatekey);
        mySign.update(encrypted.getBytes(Properties.CHAR_ENCODING));

        byte[] byteSignedData = mySign.sign();

        String SignedData = new String(Base64.encodeBase64(byteSignedData));
        return SignedData;
    }

    public static boolean verifySig(String data, PublicKey key, String sig) throws Exception {
        Signature signer = Signature.getInstance(Properties.Signature);

        byte[] databytes = (data.getBytes(Properties.CHAR_ENCODING));
        byte[] sigbytes = Base64.decodeBase64(sig.getBytes(Properties.CHAR_ENCODING));

        signer.initVerify(key);
        signer.update(databytes);
        boolean result = signer.verify(sigbytes);

        return result;
    }
}
