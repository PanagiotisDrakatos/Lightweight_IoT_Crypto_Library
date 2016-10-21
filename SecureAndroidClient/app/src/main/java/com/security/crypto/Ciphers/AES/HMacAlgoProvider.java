package com.security.crypto.Ciphers.AES;


import com.security.crypto.Configuration.Properties;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMacAlgoProvider {

    public static String HmacSign(String Data, SecretKeySpec Integritykey, String algorithm) throws Exception {
        Mac sha256_HMAC = Mac.getInstance(algorithm);
        sha256_HMAC.init(Integritykey);

        byte[] DatadBytes = Data.getBytes(Properties.CHAR_ENCODING);
        String hash = new String(Base64.encodeBase64(sha256_HMAC.doFinal(DatadBytes)));
        return hash;
    }

    public static boolean HmacVerify(String Data, SecretKeySpec Integritykey, String HmacMsg, String algorithm) throws Exception {
        String ServerHmacSign = HmacSign(Data, Integritykey, algorithm);
        if (HmacMsg.equals(ServerHmacSign)) {
            System.out.println("Integrity verified successfully");
            return true;
        } else {
            System.out.println("Integrity Of Message can not be verified");
            return false;
        }

    }
}
