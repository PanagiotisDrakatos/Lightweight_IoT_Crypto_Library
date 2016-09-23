package com.security.crypto.IOSocket;

import com.security.crypto.Configuration.CiphersForUse;

public abstract class IOCallback {

    public abstract void SendDHEncryptedMessage(String Message);

    public abstract String ReceiveDHEncryptedMessage();

    public abstract void setCiphersforUse(CiphersForUse ciphersforUse);
}
