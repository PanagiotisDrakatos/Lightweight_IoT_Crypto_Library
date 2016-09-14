package com.security.crypto.IOSocket;

import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class IOTransport {

    private Socket socket = null;
    private SSLSocket sslsocket = null;

    private PrintWriter out;
    private BufferedReader br;

    public IOTransport(Socket socket) throws IOException {
        this.socket = socket;
        set_PlainoutpuStreams();
    }

    public IOTransport(SSLSocket sslsocket) throws IOException {
        this.sslsocket = sslsocket;
        set_SecureOutPutStreams();
    }

    private void set_PlainoutpuStreams() throws IOException {
        out = new PrintWriter(socket.getOutputStream(), true);
        out.flush();
        br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    private void set_SecureOutPutStreams() throws IOException {
        out = new PrintWriter(sslsocket.getOutputStream(), true);
        out.flush();
        br = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
    }

    public void SendMessage(String toSend) throws IOException {
        out.print(toSend);
        out.flush();
    }

    public String receiveMessage() throws IOException {
        String received = br.readLine();
        return received;
    }

    public void close() throws IOException {
        out.close();
        br.close();
        if (socket != null) {
            socket.close();
        } else {
            sslsocket.close();
        }
    }

    public BufferedReader getBr() {
        return br;
    }

    public PrintWriter getOut() {
        return out;
    }

    public Socket getSocket() {
        return socket;
    }

    @Override
    public String toString() {
        return super.toString(); //To change body of generated methods, choose Tools | Templates.
    }
}
