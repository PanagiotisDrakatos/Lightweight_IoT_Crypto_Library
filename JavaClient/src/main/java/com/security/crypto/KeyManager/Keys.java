package com.security.crypto.KeyManager;


public abstract class Keys {

    private final Type type;

    public enum Type {

        SymetricKeyGenerator, DHSecretKey
    }

    //this constructor  doesn't actually "BUILD" the object, it is used to initialize fields.
    public Keys(Type type) {
        this.type = type;
    }

    public Boolean isType(Type type) {
        return (this.type == type);
    }

    @Override
    public String toString() {
        return type.toString();
    }
}
