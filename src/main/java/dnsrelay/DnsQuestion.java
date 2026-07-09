package dnsrelay;

public final class DnsQuestion {
    private final String name;
    private final int typeCode;
    private final int qclass;
    private final int startOffset;
    private final int endOffset;

    DnsQuestion(String name, int typeCode, int qclass, int startOffset, int endOffset) {
        this.name = name;
        this.typeCode = typeCode;
        this.qclass = qclass;
        this.startOffset = startOffset;
        this.endOffset = endOffset;
    }

    public String name() {
        return name;
    }

    public DnsRecordType type() {
        return DnsRecordType.fromCode(typeCode);
    }

    public int typeCode() {
        return typeCode;
    }

    public int qclass() {
        return qclass;
    }

    int startOffset() {
        return startOffset;
    }

    public int endOffset() {
        return endOffset;
    }
}
