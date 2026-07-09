package dnsrelay;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public final class DnsRelayServer {
    private static final int MAX_DNS_PACKET = 4096;
    private static final int LOCAL_TTL_SECONDS = 120;
    private static final int UPSTREAM_UDP_TIMEOUT_MILLIS = 5_000;
    private static final int UPSTREAM_TCP_TIMEOUT_MILLIS = 5_000;

    private volatile LocalDnsDatabase database;
    private final InetAddress upstreamDns;
    private final int listenPort;
    private final DnsRelayConfig.DebugLevel debugLevel;
    private final IdMapper idMapper = new IdMapper();
    private final DnsResponseCache responseCache = new DnsResponseCache();
    private final QueryStatistics statistics = new QueryStatistics();
    private final AtomicBoolean running = new AtomicBoolean(false);

    private DatagramSocket clientSocket;
    private DatagramSocket upstreamSocket;
    private ServerSocket tcpServerSocket;

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
            tcpServerSocket = new ServerSocket();
            tcpServerSocket.setReuseAddress(true);
            tcpServerSocket.bind(new InetSocketAddress(listenPort));
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

        Thread tcpThread = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptTcpConnections();
            }
        }, "dnsrelay-tcp");
        tcpThread.setDaemon(true);
        tcpThread.start();

        log(DnsRelayConfig.DebugLevel.BASIC, "Listening on UDP port " + listenPort);
        log(DnsRelayConfig.DebugLevel.BASIC, "Listening on TCP port " + listenPort);
        receiveClientQueries();
        printQueryStatistics();
    }

    public QueryStatistics statistics() {
        return statistics;
    }

    public void stop() {
        running.set(false);
        if (clientSocket != null) {
            clientSocket.close();
        }
        if (upstreamSocket != null) {
            upstreamSocket.close();
        }
        if (tcpServerSocket != null) {
            try {
                tcpServerSocket.close();
            } catch (IOException ex) {
                // Ignore shutdown errors.
            }
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
                ClientContext client = ClientContext.udp(
                        new InetSocketAddress(packet.getAddress(), packet.getPort()),
                        clientSocket);
                handleQuery(data, packet.getLength(), client);
            } catch (SocketException ex) {
                if (running.get()) {
                    System.err.println("Client socket error: " + ex.getMessage());
                }
            } catch (Exception ex) {
                System.err.println("Failed to handle client packet: " + ex.getMessage());
            }
        }
    }

    private void acceptTcpConnections() {
        while (running.get()) {
            try {
                final Socket socket = tcpServerSocket.accept();
                Thread worker = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        handleTcpConnection(socket);
                    }
                }, "dnsrelay-tcp-client");
                worker.setDaemon(true);
                worker.start();
            } catch (SocketException ex) {
                if (running.get()) {
                    System.err.println("TCP accept error: " + ex.getMessage());
                }
            } catch (IOException ex) {
                if (running.get()) {
                    System.err.println("Failed to accept TCP connection: " + ex.getMessage());
                }
            }
        }
    }

    private void handleTcpConnection(Socket socket) {
        try {
            socket.setSoTimeout(UPSTREAM_TCP_TIMEOUT_MILLIS);
            InputStream input = socket.getInputStream();
            byte[] data = ClientContext.readTcpMessage(input);
            ClientContext client = ClientContext.tcp(socket);
            handleQuery(data, data.length, client);
        } catch (Exception ex) {
            log(DnsRelayConfig.DebugLevel.BASIC, "Failed to handle TCP DNS connection: " + ex.getMessage());
            try {
                socket.close();
            } catch (IOException closeEx) {
                // Ignore close errors.
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

    private void handleQuery(byte[] data, int length, ClientContext client) throws IOException {
        DnsMessage message;
        try {
            message = DnsMessage.parse(data, length);
        } catch (DnsParseException ex) {
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Ignoring invalid DNS packet from " + client.remoteAddress() + ": " + ex.getMessage());
            return;
        }
        if (message.isResponse()) {
            log(DnsRelayConfig.DebugLevel.VERBOSE,
                    "Ignoring DNS response packet from " + client.transport() + " client: id=" + message.id());
            return;
        }
        if (message.opcode() != 0) {
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Non-standard DNS opcode " + message.opcode() + "; forwarding upstream");
            forwardQuery(data, length, message, client);
            logStatisticsSnapshot();
            return;
        }

        String queryType = describeType(message.question());
        log(DnsRelayConfig.DebugLevel.BASIC,
                "Query " + message.question().name() + " " + queryType
                        + " from " + client.transport() + " " + client.remoteAddress());
        logHeader("client", message);
        logPacketSummary("client", data, length);

        Optional<LocalResolution> localResponse = resolveLocalResponse(message);
        if (localResponse.isPresent()) {
            if (localResponse.get().blocked()) {
                statistics.recordBlocked();
            } else {
                statistics.recordLocalHit();
            }
            client.send(localResponse.get().response());
            logStatisticsSnapshot();
            return;
        }

        Optional<byte[]> cachedResponse = responseCache.lookup(
                message.question().name(),
                message.question().typeCode(),
                message.question().qclass());
        if (cachedResponse.isPresent()) {
            statistics.recordCacheHit();
            byte[] response = DnsMessage.withId(cachedResponse.get(), cachedResponse.get().length, message.id());
            client.send(response);
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Cache hit: " + message.question().name()
                            + " " + queryType
                            + " -> served from upstream cache");
            logStatisticsSnapshot();
            return;
        }

        forwardQuery(data, length, message, client);
        logStatisticsSnapshot();
    }

    private Optional<LocalResolution> resolveLocalResponse(DnsMessage message) throws IOException {
        LocalDnsDatabase currentDatabase = reloadDatabaseIfNeeded();
        Optional<LocalDnsDatabase.Entry> local = currentDatabase.lookup(message.question().name());
        if (!local.isPresent()) {
            return Optional.empty();
        }

        String queryType = describeType(message.question());
        if (local.get().isBlocked()) {
            byte[] response = DnsMessage.buildNxDomainResponse(message);
            log(DnsRelayConfig.DebugLevel.BASIC, "Local blocked: " + message.question().name() + " -> NXDOMAIN");
            return Optional.of(LocalResolution.blocked(response));
        }

        if (message.question().qclass() != 1) {
            return Optional.empty();
        }

        DnsRecordType recordType = message.question().type();
        if (recordType == DnsRecordType.CNAME && local.get().cnameTarget().isPresent()) {
            byte[] response = DnsMessage.buildCnameResponse(
                    message,
                    local.get().cnameTarget().get(),
                    LOCAL_TTL_SECONDS);
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Local hit: " + message.question().name()
                            + " CNAME -> " + local.get().cnameTarget().get());
            return Optional.of(LocalResolution.localHit(response));
        }

        if (recordType == DnsRecordType.A || recordType == DnsRecordType.AAAA) {
            List<InetAddress> addresses = local.get().addressesFor(recordType);
            if (!addresses.isEmpty()) {
                byte[] response = DnsMessage.buildAddressResponse(
                        message,
                        addresses,
                        recordType,
                        LOCAL_TTL_SECONDS);
                log(DnsRelayConfig.DebugLevel.BASIC,
                        "Local hit: " + message.question().name()
                                + " " + queryType
                                + " answers=" + addresses.size()
                                + " -> " + formatAddresses(addresses));
                return Optional.of(LocalResolution.localHit(response));
            }
            byte[] response = DnsMessage.buildEmptyResponse(message);
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Local empty: " + message.question().name()
                            + " " + queryType
                            + " -> NOERROR with 0 answers");
            return Optional.of(LocalResolution.localHit(response));
        }

        return Optional.empty();
    }

    private LocalDnsDatabase reloadDatabaseIfNeeded() {
        try {
            LocalDnsDatabase reloaded = database.reloadIfChanged(System.err);
            if (reloaded != database) {
                database = reloaded;
                responseCache.clear();
                log(DnsRelayConfig.DebugLevel.BASIC,
                        "Reloaded local DNS database; upstream cache cleared; records=" + reloaded.size());
            }
        } catch (IOException ex) {
            System.err.println("Failed to reload local DNS database: " + ex.getMessage());
        }
        return database;
    }

    private void forwardQuery(byte[] data, int length, DnsMessage message, ClientContext client) throws IOException {
        statistics.recordForwarded();
        if (client.transport() == ClientContext.Transport.TCP) {
            byte[] response = queryUpstreamSynchronously(data, length, message.id());
            client.send(response);
            return;
        }
        forwardToUpstreamAsync(data, length, message, client);
    }

    private void forwardToUpstreamAsync(byte[] data, int length, DnsMessage message, ClientContext client) throws IOException {
        IdMapper.PendingQuery pending = idMapper.register(
                message.id(),
                client,
                data,
                length,
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

    private byte[] queryUpstreamSynchronously(byte[] data, int length, int clientId) throws IOException {
        byte[] udpResponse = queryUpstreamOverUdp(data, length, clientId);
        if (!DnsMessage.isTruncated(udpResponse, udpResponse.length)) {
            storeInCache(data, length, udpResponse, udpResponse.length);
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Upstream sync response over UDP for id " + clientId + " cacheSize=" + responseCache.size());
            return udpResponse;
        }

        log(DnsRelayConfig.DebugLevel.BASIC,
                "Upstream UDP response truncated; retrying over TCP for id " + clientId);
        byte[] tcpResponse = queryUpstreamOverTcp(data, length, clientId);
        storeInCache(data, length, tcpResponse, tcpResponse.length);
        log(DnsRelayConfig.DebugLevel.BASIC,
                "Upstream sync response over TCP for id " + clientId + " cacheSize=" + responseCache.size());
        return tcpResponse;
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

        byte[] finalResponse = data;
        int finalLength = length;
        if (DnsMessage.isTruncated(data, length)) {
            log(DnsRelayConfig.DebugLevel.BASIC,
                    "Upstream UDP response truncated for id " + forwardedId + "; retrying over TCP");
            try {
                byte[] tcpResponse = queryUpstreamOverTcp(
                        pending.get().queryData(),
                        pending.get().queryData().length,
                        pending.get().originalId());
                finalResponse = tcpResponse;
                finalLength = tcpResponse.length;
            } catch (IOException ex) {
                log(DnsRelayConfig.DebugLevel.BASIC,
                        "TCP retry failed for id " + forwardedId + ": " + ex.getMessage()
                                + "; forwarding truncated UDP response");
            }
        }

        idMapper.remove(forwardedId);
        storeInCache(
                pending.get().queryName(),
                pending.get().queryType(),
                pending.get().queryClass(),
                finalResponse,
                finalLength);
        byte[] restored = DnsMessage.withId(finalResponse, finalLength, pending.get().originalId());
        pending.get().client().send(restored);
        try {
            upstreamMessage = DnsMessage.parse(finalResponse, finalLength);
        } catch (DnsParseException ex) {
            log(DnsRelayConfig.DebugLevel.VERBOSE,
                    "Final upstream response could not be parsed; using original UDP header: " + ex.getMessage());
        }
        logHeader("upstream", upstreamMessage);
        log(DnsRelayConfig.DebugLevel.VERBOSE,
                "upstream source=" + source.getHostAddress()
                        + " length=" + finalLength
                        + " rcode=" + (upstreamMessage.flags() & 0x000F));
        logPacketSummary("upstream", finalResponse, finalLength);
        log(DnsRelayConfig.DebugLevel.BASIC,
                "Upstream response id " + forwardedId + " restored to " + pending.get().originalId()
                        + " for " + pending.get().client().transport() + " " + pending.get().client().remoteAddress()
                        + " qname=" + pending.get().queryName()
                        + " qtype=" + pending.get().queryType()
                        + " cacheSize=" + responseCache.size());
    }

    private byte[] queryUpstreamOverUdp(byte[] data, int length, int clientId) throws IOException {
        DatagramSocket socket = new DatagramSocket();
        try {
            socket.setSoTimeout(UPSTREAM_UDP_TIMEOUT_MILLIS);
            byte[] query = DnsMessage.withId(data, length, clientId);
            DatagramPacket request = new DatagramPacket(
                    query,
                    query.length,
                    new InetSocketAddress(upstreamDns, DnsMessage.DNS_PORT));
            socket.send(request);
            byte[] buffer = new byte[MAX_DNS_PACKET];
            DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(responsePacket);
            byte[] response = new byte[responsePacket.getLength()];
            System.arraycopy(responsePacket.getData(), responsePacket.getOffset(), response, 0, responsePacket.getLength());
            return DnsMessage.withId(response, response.length, clientId);
        } catch (SocketTimeoutException ex) {
            throw new IOException("Upstream UDP timed out", ex);
        } finally {
            socket.close();
        }
    }

    private byte[] queryUpstreamOverTcp(byte[] data, int length, int clientId) throws IOException {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(upstreamDns, DnsMessage.DNS_PORT), UPSTREAM_TCP_TIMEOUT_MILLIS);
            socket.setSoTimeout(UPSTREAM_TCP_TIMEOUT_MILLIS);
            byte[] query = DnsMessage.withId(data, length, clientId);
            OutputStream output = socket.getOutputStream();
            output.write((query.length >>> 8) & 0xFF);
            output.write(query.length & 0xFF);
            output.write(query);
            output.flush();
            InputStream input = socket.getInputStream();
            byte[] response = ClientContext.readTcpMessage(input);
            return DnsMessage.withId(response, response.length, clientId);
        } finally {
            socket.close();
        }
    }

    private void storeInCache(String queryName, int queryType, int queryClass, byte[] response, int length) {
        responseCache.store(queryName, queryType, queryClass, response, length);
    }

    private void storeInCache(byte[] query, int queryLength, byte[] response, int responseLength) {
        try {
            DnsMessage request = DnsMessage.parse(query, queryLength);
            storeInCache(
                    request.question().name(),
                    request.question().typeCode(),
                    request.question().qclass(),
                    response,
                    responseLength);
        } catch (DnsParseException ex) {
            log(DnsRelayConfig.DebugLevel.VERBOSE, "Skipping cache store for malformed query: " + ex.getMessage());
        }
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

    private void logStatisticsSnapshot() {
        log(DnsRelayConfig.DebugLevel.BASIC, statistics.summaryLine());
    }

    private void printQueryStatistics() {
        System.out.println(statistics.summaryLine());
    }

    private static final class LocalResolution {
        private final boolean blocked;
        private final byte[] response;

        private LocalResolution(boolean blocked, byte[] response) {
            this.blocked = blocked;
            this.response = response;
        }

        static LocalResolution blocked(byte[] response) {
            return new LocalResolution(true, response);
        }

        static LocalResolution localHit(byte[] response) {
            return new LocalResolution(false, response);
        }

        boolean blocked() {
            return blocked;
        }

        byte[] response() {
            return response;
        }
    }
}
