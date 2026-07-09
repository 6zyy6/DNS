package dnsrelay;

import java.util.concurrent.atomic.AtomicLong;

public final class QueryStatistics {
    private final AtomicLong totalQueries = new AtomicLong();
    private final AtomicLong localHits = new AtomicLong();
    private final AtomicLong blocked = new AtomicLong();
    private final AtomicLong cacheHits = new AtomicLong();
    private final AtomicLong forwarded = new AtomicLong();

    public void recordLocalHit() {
        totalQueries.incrementAndGet();
        localHits.incrementAndGet();
    }

    public void recordBlocked() {
        totalQueries.incrementAndGet();
        blocked.incrementAndGet();
    }

    public void recordCacheHit() {
        totalQueries.incrementAndGet();
        cacheHits.incrementAndGet();
    }

    public void recordForwarded() {
        totalQueries.incrementAndGet();
        forwarded.incrementAndGet();
    }

    public long totalQueries() {
        return totalQueries.get();
    }

    public long localHits() {
        return localHits.get();
    }

    public long blocked() {
        return blocked.get();
    }

    public long cacheHits() {
        return cacheHits.get();
    }

    public long forwarded() {
        return forwarded.get();
    }

    public String summaryLine() {
        return "Query stats: total=" + totalQueries.get()
                + " localHit=" + localHits.get()
                + " blocked=" + blocked.get()
                + " cacheHit=" + cacheHits.get()
                + " forwarded=" + forwarded.get();
    }
}
