package com.security.crypto.IOSocket;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Arrays;

import javax.net.ssl.SSLSocket;

public class IOTransport {

    private Socket socket = null;
    private SSLSocket sslsocket = null;

    private PrintWriter out;
    private BufferedReader br;

    private BufferedOutputStream output;
    private BufferedInputStream in;

    public IOTransport(Socket socket) throws IOException {
        this.socket = socket;
        this.socket.setTcpNoDelay(true);
        set_PlainoutpuStreams();
    }

    public IOTransport(SSLSocket sslsocket) throws IOException {
        this.sslsocket = sslsocket;
        set_SecureOutPutStreams();
    }

    private void set_PlainoutpuStreams() throws IOException {
        output = new BufferedOutputStream(socket.getOutputStream());
        output.flush();
        in = new BufferedInputStream(socket.getInputStream());
    }

    private void set_SecureOutPutStreams() throws IOException {
        out = new PrintWriter(sslsocket.getOutputStream(), true);
        out.flush();
        br = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
    }

    public void SendMessage(String toSend) throws IOException {
        output.write(toSend.getBytes());
        output.flush();
    }

    public String receiveMessage() throws IOException, InterruptedException {
        StringBuilder sb = new StringBuilder();
        byte[] bytes = new byte[1024];
        int s = 0;
        int index = 0;
        while (true) {
            s = in.read();
            if (s == 10) {
                break;
            }
            bytes[index++] = (byte) (s);
            if (index == bytes.length) {
                sb.append(new String(bytes));
                bytes = new byte[1024];
                index = 0;
            }
        }
        if (index > 0) {
            sb.append(new String(Arrays.copyOfRange(bytes, 0, index)));
        }

        return sb.toString();
    }

    public void close() throws IOException {

        if (socket != null) {
            socket.close();
            output.close();
            in.close();
        } else {
            sslsocket.close();
            out.close();
            br.close();
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
