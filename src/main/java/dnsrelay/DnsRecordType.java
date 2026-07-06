package dnsrelay;

public enum DnsRecordType {
    A(1, "A"),
    AAAA(28, "AAAA"),
    UNKNOWN(-1, "UNKNOWN");

    private final int code;
    private final String displayName;

    DnsRecordType(int code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }

    public int code() {
        return code;
    }

    public String displayName() {
        return displayName;
    }

    public static DnsRecordType fromCode(int code) {
        for (DnsRecordType type : values()) {
            if (type.code == code) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
