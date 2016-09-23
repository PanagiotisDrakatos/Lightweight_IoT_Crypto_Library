package com.security.crypto.Configuration;


public class CiphersForUse {
    private String CipherAlgorithm;
    private String HashAlgorithm;


    public CiphersForUse() {
        this.CipherAlgorithm = null;
        this.HashAlgorithm = null;
    }

    public CiphersForUse(String CipherAlgorithm, String HashAlgorithm) {
        this.CipherAlgorithm = CipherAlgorithm;
        this.HashAlgorithm = HashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        HashAlgorithm = hashAlgorithm;
    }

    public void setCipherAlgorithm(String cipherAlgorithm) {
        CipherAlgorithm = cipherAlgorithm;
    }

    public String getHashAlgorithm() {
        return HashAlgorithm;
    }

    public String getCipherAlgorithm() {
        return CipherAlgorithm;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
