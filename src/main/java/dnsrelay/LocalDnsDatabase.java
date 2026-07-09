package dnsrelay;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class LocalDnsDatabase {
    private final Map<String, Entry> entries;
    private final Path sourceFile;
    private final long lastModifiedMillis;

    private LocalDnsDatabase(Map<String, Entry> entries, Path sourceFile, long lastModifiedMillis) {
        this.entries = Collections.unmodifiableMap(new HashMap<String, Entry>(entries));
        this.sourceFile = sourceFile;
        this.lastModifiedMillis = lastModifiedMillis;
    }

    public static LocalDnsDatabase load(Path file, PrintStream warnings) throws IOException {
        Map<String, Entry> entries = new HashMap<String, Entry>();
        BufferedReader reader = Files.newBufferedReader(file);
        try {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                parseLine(line, lineNumber, entries, warnings);
            }
        } finally {
            reader.close();
        }
        return new LocalDnsDatabase(entries, file, Files.getLastModifiedTime(file).toMillis());
    }

    public Optional<Entry> lookup(String name) {
        return Optional.ofNullable(entries.get(DnsName.normalize(name)));
    }

    public int size() {
        return entries.size();
    }

    public LocalDnsDatabase reloadIfChanged(PrintStream warnings) throws IOException {
        long currentLastModified = Files.getLastModifiedTime(sourceFile).toMillis();
        if (currentLastModified == lastModifiedMillis) {
            return this;
        }
        return load(sourceFile, warnings);
    }

    private static void parseLine(String rawLine, int lineNumber, Map<String, Entry> entries, PrintStream warnings) {
        String line = rawLine.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return;
        }

        String[] parts = line.split("\\s+");
        if (parts.length < 2) {
            warn(warnings, lineNumber, rawLine, "expected: IP domain or CNAME target domain");
            return;
        }

        try {
            if (parts[0].equalsIgnoreCase("CNAME")) {
                if (parts.length < 3) {
                    warn(warnings, lineNumber, rawLine, "expected: CNAME target domain");
                    return;
                }
                String target = DnsName.normalize(parts[1]);
                String domain = DnsName.normalize(parts[2]);
                DnsName.encode(target);
                DnsName.encode(domain);
                Entry existing = entries.get(domain);
                if (existing == null) {
                    existing = new Entry();
                    entries.put(domain, existing);
                }
                existing.setCnameTarget(target);
                return;
            }

            InetAddress address = parseAddress(parts[0]);
            String domain = DnsName.normalize(parts[1]);
            DnsName.encode(domain);
            Entry existing = entries.get(domain);
            if (existing == null) {
                existing = new Entry();
                entries.put(domain, existing);
            }
            existing.add(address);
        } catch (IllegalArgumentException ex) {
            warn(warnings, lineNumber, rawLine, ex.getMessage());
        }
    }

    private static InetAddress parseAddress(String value) {
        if (value.indexOf(':') >= 0) {
            try {
                InetAddress address = InetAddress.getByName(value);
                if (address.getAddress().length != 16) {
                    throw new IllegalArgumentException("invalid IPv6 address");
                }
                return address;
            } catch (UnknownHostException ex) {
                throw new IllegalArgumentException("invalid IPv6 address");
            }
        }
        return parseIpv4(value);
    }

    private static InetAddress parseIpv4(String value) {
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            throw new IllegalArgumentException("invalid IPv4 address");
        }
        byte[] bytes = new byte[4];
        for (int i = 0; i < octets.length; i++) {
            if (octets[i].isEmpty()) {
                throw new IllegalArgumentException("invalid IPv4 address");
            }
            int octet;
            try {
                octet = Integer.parseInt(octets[i]);
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("invalid IPv4 address");
            }
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("invalid IPv4 address");
            }
            bytes[i] = (byte) octet;
        }
        try {
            return InetAddress.getByAddress(bytes);
        } catch (IOException ex) {
            throw new IllegalArgumentException("invalid IPv4 address");
        }
    }

    private static void warn(PrintStream warnings, int lineNumber, String line, String reason) {
        warnings.println("Skipping invalid line " + lineNumber + ": " + line + " (" + reason + ")");
    }

    public static final class Entry {
        private final List<InetAddress> addresses = new ArrayList<InetAddress>();
        private String cnameTarget;

        void add(InetAddress address) {
            if (isBlockedAddress(address)) {
                addresses.clear();
                addresses.add(address);
                cnameTarget = null;
                return;
            }
            if (!isBlocked()) {
                addresses.add(address);
            }
        }

        void setCnameTarget(String target) {
            if (isBlocked()) {
                return;
            }
            cnameTarget = target;
        }

        public InetAddress address() {
            return addresses.get(0);
        }

        public Optional<String> cnameTarget() {
            return Optional.ofNullable(cnameTarget);
        }

        public List<InetAddress> addressesFor(DnsRecordType recordType) {
            List<InetAddress> matching = new ArrayList<InetAddress>();
            for (InetAddress address : addresses) {
                int length = address.getAddress().length;
                if (recordType == DnsRecordType.A && length == 4 && !isBlockedAddress(address)) {
                    matching.add(address);
                } else if (recordType == DnsRecordType.AAAA && length == 16) {
                    matching.add(address);
                }
            }
            return Collections.unmodifiableList(matching);
        }

        public boolean isBlocked() {
            return !addresses.isEmpty() && isBlockedAddress(addresses.get(0));
        }

        public boolean hasLocalRecordType(DnsRecordType recordType) {
            if (recordType == DnsRecordType.CNAME) {
                return cnameTarget != null;
            }
            if (recordType == DnsRecordType.A || recordType == DnsRecordType.AAAA) {
                return !addressesFor(recordType).isEmpty();
            }
            return false;
        }

        private static boolean isBlockedAddress(InetAddress address) {
            byte[] bytes = address.getAddress();
            return bytes.length == 4
                    && bytes[0] == 0
                    && bytes[1] == 0
                    && bytes[2] == 0
                    && bytes[3] == 0;
        }
    }
}
