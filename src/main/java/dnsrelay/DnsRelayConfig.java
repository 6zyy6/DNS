package dnsrelay;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class DnsRelayConfig {
    public enum DebugLevel {
        OFF,
        BASIC,
        VERBOSE
    }

    private final DebugLevel debugLevel;
    private final InetAddress upstreamDns;
    private final Path databaseFile;
    private final int listenPort;

    private DnsRelayConfig(DebugLevel debugLevel, InetAddress upstreamDns, Path databaseFile, int listenPort) {
        this.debugLevel = debugLevel;
        this.upstreamDns = upstreamDns;
        this.databaseFile = databaseFile;
        this.listenPort = listenPort;
    }

    public static DnsRelayConfig parse(String[] args) {
        DebugLevel debugLevel = DebugLevel.OFF;
        int listenPort = DnsMessage.DNS_PORT;
        List<String> positional = new ArrayList<String>();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("-d".equals(arg)) {
                debugLevel = DebugLevel.BASIC;
            } else if ("-dd".equals(arg)) {
                debugLevel = DebugLevel.VERBOSE;
            } else if ("-p".equals(arg) || "--port".equals(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing port after " + arg);
                }
                listenPort = parsePort(args[++i]);
            } else if ("-h".equals(arg) || "--help".equals(arg)) {
                throw new UsageRequestedException();
            } else {
                positional.add(arg);
            }
        }

        try {
            InetAddress upstream = InetAddress.getByName("114.114.114.114");
            Path databaseFile = Paths.get("dnsrelay.txt");
            if (positional.size() == 1) {
                if (isIpv4Literal(positional.get(0))) {
                    upstream = InetAddress.getByName(positional.get(0));
                } else {
                    databaseFile = Paths.get(positional.get(0));
                }
            } else if (positional.size() == 2) {
                if (!isIpv4Literal(positional.get(0))) {
                    throw new IllegalArgumentException("Upstream DNS must be an IPv4 address: " + positional.get(0));
                }
                upstream = InetAddress.getByName(positional.get(0));
                databaseFile = Paths.get(positional.get(1));
            } else if (positional.size() > 2) {
                throw new IllegalArgumentException("Too many arguments");
            }
            return new DnsRelayConfig(debugLevel, upstream, databaseFile, listenPort);
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid upstream DNS address", ex);
        }
    }

    public static String usage() {
        return "Usage: java dnsrelay [-d | -dd] [--port N] [dns-server-ipaddr] [filename]\n"
                + "Example: java dnsrelay -dd 114.114.114.114 dnsrelay.txt";
    }

    public DebugLevel debugLevel() {
        return debugLevel;
    }

    public InetAddress upstreamDns() {
        return upstreamDns;
    }

    public Path databaseFile() {
        return databaseFile;
    }

    public int listenPort() {
        return listenPort;
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port out of range: " + value);
            }
            return port;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid port: " + value);
        }
    }

    private static boolean isIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            } catch (NumberFormatException ex) {
                return false;
            }
        }
        return true;
    }

    public static final class UsageRequestedException extends RuntimeException {
    }
}
