package com.security.crypto.Configuration;


public class StringJoin {

    private String Delimeter;
    private StringBuilder stringbuilder;

    public StringJoin(String Delimeter) {
        this.Delimeter = Delimeter;
        this.stringbuilder = new StringBuilder();
    }

    public void add(String strToadd) {
        stringbuilder.append(strToadd);
        stringbuilder.append(Delimeter);
    }

    public String toString() {
        return stringbuilder.toString();
    }
}
