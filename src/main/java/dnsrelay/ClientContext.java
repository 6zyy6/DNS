package dnsrelay;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class ClientContext {
    public enum Transport {
        UDP,
        TCP
    }

    private final Transport transport;
    private final InetSocketAddress remoteAddress;
    private final DatagramSocket udpReplySocket;
    private final Socket tcpSocket;

    private ClientContext(
            Transport transport,
            InetSocketAddress remoteAddress,
            DatagramSocket udpReplySocket,
            Socket tcpSocket) {
        this.transport = transport;
        this.remoteAddress = remoteAddress;
        this.udpReplySocket = udpReplySocket;
        this.tcpSocket = tcpSocket;
    }

    public static ClientContext udp(InetSocketAddress remoteAddress, DatagramSocket replySocket) {
        return new ClientContext(Transport.UDP, remoteAddress, replySocket, null);
    }

    public static ClientContext tcp(Socket socket) {
        InetSocketAddress remoteAddress = (InetSocketAddress) socket.getRemoteSocketAddress();
        return new ClientContext(Transport.TCP, remoteAddress, null, socket);
    }

    public Transport transport() {
        return transport;
    }

    public InetSocketAddress remoteAddress() {
        return remoteAddress;
    }

    public void send(byte[] response) throws IOException {
        if (transport == Transport.UDP) {
            DatagramPacket packet = new DatagramPacket(response, response.length, remoteAddress);
            udpReplySocket.send(packet);
            return;
        }
        OutputStream output = tcpSocket.getOutputStream();
        output.write((response.length >>> 8) & 0xFF);
        output.write(response.length & 0xFF);
        output.write(response);
        output.flush();
        tcpSocket.close();
    }

    public static byte[] readTcpMessage(InputStream input) throws IOException {
        int lengthHigh = input.read();
        int lengthLow = input.read();
        if (lengthHigh < 0 || lengthLow < 0) {
            throw new IOException("Unexpected end of TCP DNS stream");
        }
        int length = (lengthHigh << 8) | lengthLow;
        if (length <= 0 || length > 65535) {
            throw new IOException("Invalid TCP DNS message length: " + length);
        }
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.read(data, offset, length - offset);
            if (read < 0) {
                throw new IOException("Unexpected end of TCP DNS stream");
            }
            offset += read;
        }
        return data;
    }
}
