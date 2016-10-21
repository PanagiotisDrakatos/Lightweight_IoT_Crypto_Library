package com.security.crypto.IOSocket;

import com.security.crypto.Configuration.CiphersForUse;

import org.json.JSONException;

import java.io.IOException;

public abstract class IOSynAck {

    public abstract void SendPlainMessage() throws IOException, JSONException;

    public abstract void ReceiveServerCertificate() throws Exception;

    public abstract void ResendCookieServer() throws IOException, JSONException;

    public abstract void SendPublicValue() throws IOException;

    public abstract void ReceivePublicValue() throws Exception;

    public abstract void SendCipherSuites() throws Exception;

    public abstract CiphersForUse ReceiveCipherSuites() throws Exception;
}
