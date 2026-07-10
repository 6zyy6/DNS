package dnsrelay;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class DnsResponseCache {
    private static final int DEFAULT_NEGATIVE_TTL_SECONDS = 60;
    private static final int MAX_TTL_SECONDS = 3600;
    private static final int MIN_TTL_SECONDS = 1;

    private final ConcurrentHashMap<CacheKey, CacheEntry> entries = new ConcurrentHashMap<CacheKey, CacheEntry>();

    public Optional<byte[]> lookup(String name, int queryType, int queryClass) {
        CacheKey key = CacheKey.of(name, queryType, queryClass);
        CacheEntry entry = entries.get(key);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.isExpired()) {
            entries.remove(key, entry);
            return Optional.empty();
        }
        return Optional.of(Arrays.copyOf(entry.response(), entry.response().length));
    }

    public void store(String name, int queryType, int queryClass, byte[] response, int length) {
        int ttlSeconds = clampTtl(extractTtlSeconds(response, length));
        long expiresAtMillis = System.currentTimeMillis() + ttlSeconds * 1000L;
        CacheKey key = CacheKey.of(name, queryType, queryClass);
        entries.put(key, new CacheEntry(Arrays.copyOf(response, length), expiresAtMillis));
    }

    public void clear() {
        entries.clear();
    }

    public int size() {
        cleanupExpired();
        return entries.size();
    }

    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        for (Map.Entry<CacheKey, CacheEntry> entry : entries.entrySet()) {
            if (entry.getValue().isExpired(now)) {
                entries.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    public static int effectiveCacheTtlSeconds(byte[] data, int length) {
        return clampTtl(extractTtlSeconds(data, length));
    }

    public static int extractTtlSeconds(byte[] data, int length) {
        if (length < DnsMessage.HEADER_LENGTH) {
            return DEFAULT_NEGATIVE_TTL_SECONDS;
        }
        int answerCount = unsignedShort(data, 6);
        int authorityCount = unsignedShort(data, 8);
        int additionalCount = unsignedShort(data, 10);
        int rcode = unsignedShort(data, 2) & 0x000F;

        int cursor;
        try {
            DnsMessage message = DnsMessage.parse(data, length);
            cursor = message.question().endOffset();
        } catch (DnsParseException ex) {
            return DEFAULT_NEGATIVE_TTL_SECONDS;
        }

        int minTtl = Integer.MAX_VALUE;
        int recordCount = answerCount + authorityCount + additionalCount;
        for (int i = 0; i < recordCount; i++) {
            cursor = skipName(data, cursor, length);
            if (cursor < 0 || cursor + 10 > length) {
                break;
            }
            long ttl = unsignedInt(data, cursor + 4) & 0xFFFFFFFFL;
            int rdLength = unsignedShort(data, cursor + 8);
            if (ttl < minTtl) {
                minTtl = (int) Math.min(ttl, Integer.MAX_VALUE);
            }
            cursor += 10 + rdLength;
            if (cursor > length) {
                break;
            }
        }

        if (minTtl != Integer.MAX_VALUE) {
            return minTtl;
        }
        if (rcode != 0) {
            return DEFAULT_NEGATIVE_TTL_SECONDS;
        }
        return MIN_TTL_SECONDS;
    }

    private static int clampTtl(int ttlSeconds) {
        if (ttlSeconds < MIN_TTL_SECONDS) {
            return MIN_TTL_SECONDS;
        }
        if (ttlSeconds > MAX_TTL_SECONDS) {
            return MAX_TTL_SECONDS;
        }
        return ttlSeconds;
    }

    private static int skipName(byte[] data, int offset, int limit) {
        int cursor = offset;
        while (cursor < limit) {
            int length = data[cursor] & 0xFF;
            if ((length & 0xC0) == 0xC0) {
                return cursor + 2;
            }
            if (length == 0) {
                return cursor + 1;
            }
            if (length > 63) {
                return -1;
            }
            cursor += 1 + length;
            if (cursor > limit) {
                return -1;
            }
        }
        return -1;
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long unsignedInt(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private static final class CacheKey {
        private final String name;
        private final int queryType;
        private final int queryClass;

        private CacheKey(String name, int queryType, int queryClass) {
            this.name = name;
            this.queryType = queryType;
            this.queryClass = queryClass;
        }

        static CacheKey of(String name, int queryType, int queryClass) {
            return new CacheKey(DnsName.normalize(name), queryType, queryClass);
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof CacheKey)) {
                return false;
            }
            CacheKey that = (CacheKey) other;
            return name.equals(that.name)
                    && queryType == that.queryType
                    && queryClass == that.queryClass;
        }

        @Override
        public int hashCode() {
            int result = name.hashCode();
            result = 31 * result + queryType;
            result = 31 * result + queryClass;
            return result;
        }
    }

    private static final class CacheEntry {
        private final byte[] response;
        private final long expiresAtMillis;

        CacheEntry(byte[] response, long expiresAtMillis) {
            this.response = response;
            this.expiresAtMillis = expiresAtMillis;
        }

        byte[] response() {
            return response;
        }

        boolean isExpired() {
            return isExpired(System.currentTimeMillis());
        }

        boolean isExpired(long nowMillis) {
            return nowMillis >= expiresAtMillis;
        }
    }
}
