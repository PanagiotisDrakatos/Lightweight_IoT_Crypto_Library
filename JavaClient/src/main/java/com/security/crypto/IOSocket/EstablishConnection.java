package com.security.crypto.IOSocket;

import com.security.crypto.Configuration.Properties;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EstablishConnection {

    private Socket socket;
    private SSLSocket sslsocket;
    private IOTransport transport;
    private static final String currentPath = System.getProperty("user.dir") + "/SSLStore/";
    private static final String Password = "password";
    private boolean result;

    public EstablishConnection(String connection) {
        try {

            result = (connection.equals("PlainTextConnection")) ? SetupPlainConnection() : SslTlsv2Connection();
            setResult(result);
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | KeyManagementException ex) {
            Logger.getLogger(EstablishConnection.class.getName()).log(Level.SEVERE, null, ex);
        }
    }


    private boolean SetupPlainConnection() throws IOException {
        try {
            System.out.println("Creating socket to '" + Properties.host + "' on port " + Properties.portNumber);

            socket = new Socket(Properties.host, Properties.portNumber);
            transport = new IOTransport(socket);

            System.out.println("ESTABLISHED" + "\n");
            System.out.println("Just connected to " + socket.getInetAddress() + "\n");
        } catch (ConnectException ex) {
            System.out.println("Connection failed Server probably down try  again later");
            System.exit(0);
        }
        return true;
    }

    private boolean SslTlsv2Connection() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        KeyStore client = KeyStore.getInstance("JKS");
        client.load(new FileInputStream(currentPath + "clientcert.keystore"), Password.toCharArray());

        KeyStore trust = KeyStore.getInstance("JKS");
        trust.load(new FileInputStream(currentPath + "myTrustStore.keystore"), Password.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(client, Password.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(trust);

        SSLContext sc = SSLContext.getInstance("SSL");
        TrustManager[] trustManagers = tmf.getTrustManagers();
        sc.init(kmf.getKeyManagers(), trustManagers, new java.security.SecureRandom());

        SSLSocketFactory ssf = sc.getSocketFactory();
        sslsocket = (SSLSocket) ssf.createSocket(Properties.host, Properties.portNumber);

        System.out.println("ESTABLISHED" + "\n");
        System.out.println("Just connected to " + sslsocket.getInetAddress() + "\n");

        transport = new IOTransport(sslsocket);
        return false;
    }

    //overload functions
    private boolean SetupPlainConnection(int timeout) throws IOException {
        System.out.println("Creating socket to '" + Properties.host + "' on port " + Properties.portNumber);

        socket = new Socket();
        socket.connect(new InetSocketAddress(Properties.host, Properties.portNumber), timeout);
        transport = new IOTransport(socket);

        System.out.println("ESTABLISHED" + "\n");
        System.out.println("Just connected to " + socket.getInetAddress() + "\n");
        return true;
    }

    private boolean SslTlsv2Connection(int timeout) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        KeyStore client = KeyStore.getInstance("JKS");
        client.load(new FileInputStream(currentPath + "clientcert.keystore"), Password.toCharArray());

        KeyStore trust = KeyStore.getInstance("JKS");
        trust.load(new FileInputStream(currentPath + "myTrustStore.keystore"), Password.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(client, Password.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(trust);

        SSLContext sc = SSLContext.getInstance("SSL");
        TrustManager[] trustManagers = tmf.getTrustManagers();
        sc.init(kmf.getKeyManagers(), trustManagers, new java.security.SecureRandom());

        SSLSocketFactory ssf = sc.getSocketFactory();
        sslsocket = (SSLSocket) ssf.createSocket();
        sslsocket.connect(new InetSocketAddress(Properties.host, Properties.portNumber), timeout);

        System.out.println("ESTABLISHED" + "\n");
        System.out.println("Just connected to " + sslsocket.getInetAddress() + "\n");

        transport = new IOTransport(sslsocket);
        return false;
    }

    public IOTransport getTransport() {
        return transport;
    }

    private void setResult(boolean result) {
        this.result = result;
    }

    public boolean isResult() {
        return result;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
