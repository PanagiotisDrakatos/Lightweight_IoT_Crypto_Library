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
        if (HashAlgorithm.contains("SHA256"))
            this.HashAlgorithm = Properties.MACSHA_256;
        else if (HashAlgorithm.contains("SHA1"))
            this.HashAlgorithm = Properties.MACSHA1;
        else
            this.HashAlgorithm = Properties.MACSHA1;
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
