package dnsrelay;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public final class IdMapper {
    private static final long EXPIRE_AFTER_MILLIS = 30_000L;

    private final ConcurrentHashMap<Integer, PendingQuery> pending = new ConcurrentHashMap<Integer, PendingQuery>();
    private final AtomicInteger sequence;

    public IdMapper() {
        this.sequence = new AtomicInteger(new SecureRandom().nextInt(0x10000));
    }

    public PendingQuery register(
            int originalId,
            ClientContext client,
            byte[] queryData,
            int queryLength,
            String queryName,
            int queryType,
            int queryClass) {
        cleanupExpired();
        byte[] queryCopy = new byte[queryLength];
        System.arraycopy(queryData, 0, queryCopy, 0, queryLength);
        for (int attempts = 0; attempts < 0x10000; attempts++) {
            int forwardedId = sequence.getAndIncrement() & 0xFFFF;
            if (forwardedId == (originalId & 0xFFFF)) {
                continue;
            }
            PendingQuery query = new PendingQuery(
                    originalId & 0xFFFF,
                    forwardedId,
                    client,
                    queryCopy,
                    queryName,
                    queryType,
                    queryClass,
                    System.currentTimeMillis());
            if (pending.putIfAbsent(forwardedId, query) == null) {
                return query;
            }
        }
        throw new IllegalStateException("No free DNS transaction id is available");
    }

    public Optional<PendingQuery> remove(int forwardedId) {
        return Optional.ofNullable(pending.remove(forwardedId & 0xFFFF));
    }

    public Optional<PendingQuery> lookup(int forwardedId) {
        return Optional.ofNullable(pending.get(forwardedId & 0xFFFF));
    }

    public int size() {
        return pending.size();
    }

    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        for (Map.Entry<Integer, PendingQuery> entry : pending.entrySet()) {
            if (now - entry.getValue().createdAtMillis() > EXPIRE_AFTER_MILLIS) {
                pending.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    public static final class PendingQuery {
        private final int originalId;
        private final int forwardedId;
        private final ClientContext client;
        private final byte[] queryData;
        private final String queryName;
        private final int queryType;
        private final int queryClass;
        private final long createdAtMillis;

        PendingQuery(
                int originalId,
                int forwardedId,
                ClientContext client,
                byte[] queryData,
                String queryName,
                int queryType,
                int queryClass,
                long createdAtMillis) {
            this.originalId = originalId;
            this.forwardedId = forwardedId;
            this.client = client;
            this.queryData = queryData;
            this.queryName = queryName;
            this.queryType = queryType;
            this.queryClass = queryClass;
            this.createdAtMillis = createdAtMillis;
        }

        public int originalId() {
            return originalId;
        }

        public int forwardedId() {
            return forwardedId;
        }

        public ClientContext client() {
            return client;
        }

        public byte[] queryData() {
            return queryData;
        }

        public String queryName() {
            return queryName;
        }

        public int queryType() {
            return queryType;
        }

        public int queryClass() {
            return queryClass;
        }

        long createdAtMillis() {
            return createdAtMillis;
        }
    }
}
