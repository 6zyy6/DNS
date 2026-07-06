package dnsrelay;

import java.io.IOException;

public final class DnsRelay {
    private DnsRelay() {
    }

    public static void main(String[] args) {
        DnsRelayConfig config;
        try {
            config = DnsRelayConfig.parse(args);
        } catch (DnsRelayConfig.UsageRequestedException ex) {
            System.out.println(DnsRelayConfig.usage());
            return;
        } catch (IllegalArgumentException ex) {
            System.err.println(ex.getMessage());
            System.err.println(DnsRelayConfig.usage());
            System.exit(2);
            return;
        }

        LocalDnsDatabase database;
        try {
            database = LocalDnsDatabase.load(config.databaseFile(), System.err);
        } catch (IOException ex) {
            System.err.println("Failed to read local DNS database: " + config.databaseFile() + " (" + ex.getMessage() + ")");
            System.exit(1);
            return;
        }

        System.out.println("DNS Relay starting");
        System.out.println("Upstream DNS: " + config.upstreamDns().getHostAddress() + ":53");
        System.out.println("Listen UDP port: " + config.listenPort());
        System.out.println("Database file: " + config.databaseFile());
        System.out.println("Loaded records: " + database.size());
        System.out.println("Debug mode: " + config.debugLevel());
        System.out.println("AAAA policy: local IPv6 entries answer AAAA; domains without matching local record type are forwarded upstream unless blocked by 0.0.0.0");

        final DnsRelayServer server = new DnsRelayServer(
                database,
                config.upstreamDns(),
                config.listenPort(),
                config.debugLevel());
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                server.stop();
            }
        }));

        try {
            server.start();
        } catch (IOException ex) {
            System.err.println("DNS Relay failed: " + ex.getMessage());
            if (config.listenPort() == DnsMessage.DNS_PORT) {
                System.err.println("Binding UDP 53 usually requires Administrator/root permission.");
            }
            System.exit(1);
        }
    }
}
