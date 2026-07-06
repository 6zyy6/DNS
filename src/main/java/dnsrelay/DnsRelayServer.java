package dnsrelay;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public final class DnsRelayServer {
    private static final int MAX_DNS_PACKET = 4096;
    private static final int LOCAL_TTL_SECONDS = 120;

    private volatile LocalDnsDatabase database;
    private final InetAddress upstreamDns;
    private final int listenPort;
    private final DnsRelayConfig.DebugLevel debugLevel;
    private final IdMapper idMapper = new IdMapper();
    private final AtomicBoolean running = new AtomicBoolean(false);

    private DatagramSocket clientSocket;
    private DatagramSocket upstreamSocket;

    public DnsRelayServer(
            LocalDnsDatabase database,
            InetAddress upstreamDns,
            int listenPort,
            DnsRelayConfig.DebugLevel debugLevel) {
        this.database = database;
        this.upstreamDns = upstreamDns;
        this.listenPort = listenPort;
        this.debugLevel = debugLevel;
    }

    public void start() throws IOException {
        try {
            clientSocket = new DatagramSocket(null);
            clientSocket.setReuseAddress(true);
            clientSocket.bind(new InetSocketAddress(listenPort));
            upstreamSocket = new DatagramSocket();
            running.set(true);
        } catch (IOException ex) {
            stop();
            throw ex;
        }

        Thread upstreamThread = new Thread(new Runnable() {
            @Override
            public void run() {
                receiveUpstreamResponses();
            }
        }, "dnsrelay-upstream");
        upstreamThread.setDaemon(true);
        upstreamThread.start();

        log(DnsRelayConfig.DebugLevel.BASIC, "Listening on UDP port " + listenPort);
        receiveClientQueries();
    }

    public void stop() {
        running.set(false);
        if (clientSocket != null) {
            clientSocket.close();
        }
        if (upstreamSocket != null) {
            upstreamSocket.close();
        }
    }

    private void receiveClientQueries() {
        byte[] buffer = new byte[MAX_DNS_PACKET];
        while (running.get()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                clientSocket.receive(packet);
                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());
                InetSocketAddress client = new InetSocketAddress(packet.getAddress(), packet.getPort());
                handleClientPacket(data, packet.getLength(), client);
            } catch (SocketException ex) {
                if (running.get()) {
                    System.err.println("Client socket error: " + ex.getMessage());
                }
            } catch (Exception ex) {
                System.err.println("Failed to handle client packet: " + ex.getMessage());
            }
        }
    }

    private void receiveUpstreamResponses() {
        byte[] buffer = new byte[MAX_DNS_PACKET];
        while (running.get()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                upstreamSocket.receive(packet);
                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());
                handleUpstreamPacket(data, packet.getLength(), packet.getAddress(), packet.getPort());
            } catch (SocketException ex) {
                if (running.get()) {
                    System.err.println("Upstream socket error: " + ex.getMessage());
                }
            } catch (Exception ex) {
                System.err.println("Failed to handle upstream packet: " + ex.getMessage());
            }
        }
    }

    private void handleClientPacket(byte[] data, int length, InetSocketAddress client) throws IOException {
        DnsMessage message;
        try {
            message = DnsMessage.parse(data, length);
        } catch (DnsParseException ex) {
            log(DnsRelayConfig.DebugLevel.BASIC, "Ignoring invalid DNS packet from " + client + ": " + ex.getMessage());
            return;
        }
        if (message.isResponse()) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Ignoring DNS response packet from client socket: id=" + message.id());
            return;
        }
        if (message.opcode() != 0) {
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Non-standard DNS opcode " + message.opcode() + "; forwarding upstream");
            forwardToUpstream(data, length, message, client);
            return;
        }

        String queryType = describeType(message.question());
        log(DnsRelayConfig.DebugLevel.BASIC,
                "Query " + message.question().name() + " " + queryType + " from " + client);
        logHeader("client", message);
        logPacketSummary("client", data, length);

        LocalDnsDatabase currentDatabase = reloadDatabaseIfNeeded();
        Optional<LocalDnsDatabase.Entry> local = currentDatabase.lookup(message.question().name());
        if (local.isPresent() && local.get().isBlocked()) {
            byte[] response = DnsMessage.buildNxDomainResponse(message);
            sendToClient(response, client);
            log(DnsRelayConfig.DebugLevel.BASIC, "Local blocked: " + message.question().name() + " -> NXDOMAIN");
            return;
        }

        if (local.isPresent() && message.question().qclass() == 1) {
            List<InetAddress> addresses = local.get().addressesFor(message.question().type());
            if (!addresses.isEmpty()) {
                byte[] response = DnsMessage.buildAddressResponse(
                        message,
                        addresses,
                        message.question().type(),
                        LOCAL_TTL_SECONDS);
                sendToClient(response, client);
                log(DnsRelayConfig.DebugLevel.BASIC,
                        "Local hit: " + message.question().name()
                                + " " + queryType
                                + " answers=" + addresses.size()
                                + " -> " + formatAddresses(addresses));
                return;
            }
            if (message.question().type() == DnsRecordType.A || message.question().type() == DnsRecordType.AAAA) {
                log(DnsRelayConfig.DebugLevel.BASIC,
                        "Local domain exists but has no " + queryType + " record; forwarding upstream");
            }
        }
        forwardToUpstream(data, length, message, client);
    }

    private LocalDnsDatabase reloadDatabaseIfNeeded() {
        try {
            LocalDnsDatabase reloaded = database.reloadIfChanged(System.err);
            if (reloaded != database) {
                database = reloaded;
                log(DnsRelayConfig.DebugLevel.BASIC, "Reloaded local DNS database; records=" + reloaded.size());
            }
        } catch (IOException ex) {
            System.err.println("Failed to reload local DNS database: " + ex.getMessage());
        }
        return database;
    }

    private void handleUpstreamPacket(byte[] data, int length, InetAddress source, int sourcePort) throws IOException {
        if (!source.equals(upstreamDns)) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Ignoring packet from unexpected upstream source " + source.getHostAddress());
            return;
        }
        if (sourcePort != DnsMessage.DNS_PORT) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Ignoring packet from unexpected upstream port " + sourcePort);
            return;
        }
        if (length < 2) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Ignoring too-short upstream packet");
            return;
        }
        int forwardedId = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
        Optional<IdMapper.PendingQuery> pending = idMapper.lookup(forwardedId);
        if (!pending.isPresent()) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "No client mapping for upstream id " + forwardedId);
            return;
        }
        DnsMessage upstreamMessage;
        try {
            upstreamMessage = DnsMessage.parse(data, length);
        } catch (DnsParseException ex) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Ignoring malformed upstream response: " + ex.getMessage());
            return;
        }
        if (!upstreamMessage.isResponse()) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Ignoring upstream packet without response bit");
            return;
        }
        if (!pending.get().queryName().equals(upstreamMessage.question().name())
                || pending.get().queryType() != upstreamMessage.question().typeCode()
                || pending.get().queryClass() != upstreamMessage.question().qclass()) {
            log(DnsRelayConfig.DebugLevel.VERBOSE,
                    "Ignoring upstream response with mismatched question for id " + forwardedId);
            return;
        }
        idMapper.remove(forwardedId);
        byte[] restored = DnsMessage.withId(data, length, pending.get().originalId());
        sendToClient(restored, pending.get().client());
        logHeader("upstream", upstreamMessage);
        log(DnsRelayConfig.DebugLevel.VERBOSE,
                "upstream source=" + source.getHostAddress()
                        + " length=" + length
                        + " rcode=" + (upstreamMessage.flags() & 0x000F));
        logPacketSummary("upstream", data, length);
        log(DnsRelayConfig.DebugLevel.BASIC,
                "Upstream response id " + forwardedId + " restored to " + pending.get().originalId()
                        + " for " + pending.get().client()
                        + " qname=" + pending.get().queryName()
                        + " qtype=" + pending.get().queryType());
    }

    private void forwardToUpstream(byte[] data, int length, DnsMessage message, InetSocketAddress client) throws IOException {
        IdMapper.PendingQuery pending = idMapper.register(
                message.id(),
                client,
                message.question().name(),
                message.question().typeCode(),
                message.question().qclass());
        byte[] forwarded = DnsMessage.withId(data, length, pending.forwardedId());
        DatagramPacket packet = new DatagramPacket(
                forwarded,
                forwarded.length,
                new InetSocketAddress(upstreamDns, DnsMessage.DNS_PORT));
        try {
            upstreamSocket.send(packet);
        } catch (IOException ex) {
            idMapper.remove(pending.forwardedId());
            throw ex;
        }
        log(DnsRelayConfig.DebugLevel.BASIC,
                "Forwarded upstream: " + message.question().name() + " originalId=" + message.id()
                        + " forwardedId=" + pending.forwardedId());
        logPacketSummary("forwarded", forwarded, forwarded.length);
    }

    private void sendToClient(byte[] response, InetSocketAddress client) throws IOException {
        DatagramPacket packet = new DatagramPacket(response, response.length, client);
        clientSocket.send(packet);
    }

    private void logHeader(String source, DnsMessage message) {
        log(DnsRelayConfig.DebugLevel.VERBOSE,
                source + " header id=" + message.id()
                        + " flags=0x" + Integer.toHexString(message.flags())
                        + " qd=" + message.questionCount()
                        + " an=" + message.answerCount()
                        + " ns=" + message.authorityCount()
                        + " ar=" + message.additionalCount()
                        + " type=" + describeType(message.question()));
    }

    private void logPacketSummary(String source, byte[] data, int length) {
        if (debugLevel.ordinal() < DnsRelayConfig.DebugLevel.VERBOSE.ordinal()) {
            return;
        }
        int previewLength = Math.min(length, 32);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < previewLength; i++) {
            if (i > 0) {
                hex.append(' ');
            }
            int value = data[i] & 0xFF;
            if (value < 0x10) {
                hex.append('0');
            }
            hex.append(Integer.toHexString(value));
        }
        log(DnsRelayConfig.DebugLevel.VERBOSE,
                source + " packet length=" + length + " hex32=" + hex);
    }

    private String describeType(DnsQuestion question) {
        if (question.type() == DnsRecordType.UNKNOWN) {
            return "TYPE" + question.typeCode();
        }
        return question.type().displayName();
    }

    private String formatAddresses(List<InetAddress> addresses) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < addresses.size(); i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append(addresses.get(i).getHostAddress());
        }
        return builder.toString();
    }

    private void log(DnsRelayConfig.DebugLevel minimum, String message) {
        if (debugLevel.ordinal() >= minimum.ordinal()) {
            System.out.println(message);
        }
    }
}
