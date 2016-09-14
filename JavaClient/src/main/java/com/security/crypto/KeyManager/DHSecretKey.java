package com.security.crypto.KeyManager;


public class DHSecretKey extends Keys {

    private String SessionKey;

    public DHSecretKey() {
        super(Type.DHSecretKey);
        System.out.println(this.toString() + " created!");
    }

    public DHSecretKey(String SessionKey) {
        super(Type.DHSecretKey);
        this.SessionKey = SessionKey;
        System.out.println(this.toString() + " created!");
    }

    public void setSessionKey(String SessionKey) {
        this.SessionKey = SessionKey;
    }

    public String getSessionKey() {
        return SessionKey;
    }

    @Override
    public String toString() {
        return super.toString(); //To change body of generated methods, choose Tools | Templates.
    }

}
