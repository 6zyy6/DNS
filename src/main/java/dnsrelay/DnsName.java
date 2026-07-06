package dnsrelay;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class DnsName {
    private DnsName() {
    }

    public static String normalize(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Domain name is null");
        }
        String normalized = name.trim().toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Domain name is empty");
        }
        return normalized;
    }

    public static byte[] encode(String normalizedName) {
        String name = normalize(normalizedName);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String[] labels = name.split("\\.");
        int totalLength = 1;
        for (String label : labels) {
            validateLabel(label);
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            out.write(labelBytes.length);
            out.write(labelBytes, 0, labelBytes.length);
            totalLength += 1 + labelBytes.length;
        }
        if (totalLength > 255) {
            throw new IllegalArgumentException("Domain name is too long: " + normalizedName);
        }
        out.write(0);
        return out.toByteArray();
    }

    static ParsedName parse(byte[] data, int offset, int limit) throws DnsParseException {
        List<String> labels = new ArrayList<String>();
        int cursor = offset;
        int nextOffset = -1;
        int jumps = 0;

        while (true) {
            if (cursor >= limit) {
                throw new DnsParseException("DNS name exceeds packet length");
            }
            int length = data[cursor] & 0xFF;
            if ((length & 0xC0) == 0xC0) {
                throw new DnsParseException("Compressed DNS names are not accepted in questions");
            }
            if ((length & 0xC0) != 0) {
                throw new DnsParseException("Unsupported DNS label encoding");
            }
            cursor++;
            if (length == 0) {
                if (nextOffset < 0) {
                    nextOffset = cursor;
                }
                break;
            }
            if (length > 63) {
                throw new DnsParseException("DNS label is longer than 63 bytes");
            }
            if (cursor + length > limit) {
                throw new DnsParseException("Truncated DNS label");
            }
            String label = new String(data, cursor, length, StandardCharsets.US_ASCII);
            try {
                validateLabel(label);
            } catch (IllegalArgumentException ex) {
                throw new DnsParseException(ex.getMessage());
            }
            labels.add(label);
            cursor += length;
        }

        if (labels.isEmpty()) {
            throw new DnsParseException("Root DNS name is not supported for relay queries");
        }
        return new ParsedName(normalize(String.join(".", labels)), nextOffset);
    }

    private static void validateLabel(String label) {
        if (label.isEmpty()) {
            throw new IllegalArgumentException("Domain name contains an empty label");
        }
        if (label.length() > 63) {
            throw new IllegalArgumentException("Domain label is too long: " + label);
        }
        for (int i = 0; i < label.length(); i++) {
            char ch = label.charAt(i);
            boolean ok = (ch >= 'a' && ch <= 'z')
                    || (ch >= 'A' && ch <= 'Z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '-';
            if (!ok) {
                throw new IllegalArgumentException("Domain label contains non-ASCII DNS character: " + label);
            }
        }
    }

    static final class ParsedName {
        private final String name;
        private final int nextOffset;

        ParsedName(String name, int nextOffset) {
            this.name = name;
            this.nextOffset = nextOffset;
        }

        String name() {
            return name;
        }

        int nextOffset() {
            return nextOffset;
        }
    }
}
