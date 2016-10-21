package com.security.crypto.Configuration;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CookieGen {

    private String CookieServer;
    private static String DEF_RANDOM_ALGORITHM = "SHA1PRNG";
    private static int seedByteCount = 10;

    public CookieGen() {
    }

    public String GenerateCookie() {
        try {
            SecureRandom secureRandomGenerator;
            secureRandomGenerator = SecureRandom.getInstance(DEF_RANDOM_ALGORITHM);
            byte[] seed = secureRandomGenerator.generateSeed(seedByteCount);
            secureRandomGenerator.setSeed(seed);
            double value = secureRandomGenerator.nextDouble();
            System.out.println(" Secure Random # generated using setSeed(byte[]) is  " + value);
            return String.valueOf(value);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    public void setCookieServer(String cookieServer) {
        CookieServer = cookieServer;
    }

    public String getCookieServer() {
        return CookieServer;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
