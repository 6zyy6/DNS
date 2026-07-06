package dnsrelay;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

public final class DnsMessage {
    public static final int DNS_PORT = 53;
    private static final int HEADER_LENGTH = 12;
    private static final int CLASS_IN = 1;

    private final byte[] packet;
    private final int id;
    private final int flags;
    private final int questionCount;
    private final int answerCount;
    private final int authorityCount;
    private final int additionalCount;
    private final DnsQuestion question;

    private DnsMessage(
            byte[] packet,
            int id,
            int flags,
            int questionCount,
            int answerCount,
            int authorityCount,
            int additionalCount,
            DnsQuestion question) {
        this.packet = packet;
        this.id = id;
        this.flags = flags;
        this.questionCount = questionCount;
        this.answerCount = answerCount;
        this.authorityCount = authorityCount;
        this.additionalCount = additionalCount;
        this.question = question;
    }

    public static DnsMessage parse(byte[] data, int length) throws DnsParseException {
        if (length < HEADER_LENGTH) {
            throw new DnsParseException("DNS packet shorter than header");
        }
        byte[] packet = Arrays.copyOf(data, length);
        int id = unsignedShort(packet, 0);
        int flags = unsignedShort(packet, 2);
        int qdCount = unsignedShort(packet, 4);
        int anCount = unsignedShort(packet, 6);
        int nsCount = unsignedShort(packet, 8);
        int arCount = unsignedShort(packet, 10);
        if (qdCount != 1) {
            throw new DnsParseException("DNS packet must contain exactly one question");
        }

        DnsName.ParsedName parsedName = DnsName.parse(packet, HEADER_LENGTH, length);
        int cursor = parsedName.nextOffset();
        if (cursor + 4 > length) {
            throw new DnsParseException("DNS question is missing type or class");
        }
        int typeCode = unsignedShort(packet, cursor);
        int qclass = unsignedShort(packet, cursor + 2);
        DnsQuestion question = new DnsQuestion(parsedName.name(), typeCode, qclass, HEADER_LENGTH, cursor + 4);
        return new DnsMessage(packet, id, flags, qdCount, anCount, nsCount, arCount, question);
    }

    public static byte[] buildAResponse(DnsMessage request, InetAddress ipv4, int ttlSeconds) {
        return buildAddressResponse(request, Arrays.asList(ipv4), DnsRecordType.A, ttlSeconds);
    }

    public static byte[] buildAddressResponse(
            DnsMessage request,
            List<InetAddress> addresses,
            DnsRecordType recordType,
            int ttlSeconds) {
        if (recordType != DnsRecordType.A && recordType != DnsRecordType.AAAA) {
            throw new IllegalArgumentException("Address response requires A or AAAA type");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeHeader(out, request, 0, addresses.size());
        writeQuestion(out, request);
        for (InetAddress inetAddress : addresses) {
            byte[] address = inetAddress.getAddress();
            int expectedLength = recordType == DnsRecordType.A ? 4 : 16;
            if (address.length != expectedLength) {
                throw new IllegalArgumentException(recordType.displayName() + " response received wrong address family");
            }
            writeShort(out, 0xC00C);
            writeShort(out, recordType.code());
            writeShort(out, CLASS_IN);
            writeInt(out, ttlSeconds);
            writeShort(out, address.length);
            out.write(address, 0, address.length);
        }
        return out.toByteArray();
    }

    public static byte[] buildNxDomainResponse(DnsMessage request) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeHeader(out, request, 3, 0);
        writeQuestion(out, request);
        return out.toByteArray();
    }

    public static byte[] withId(byte[] data, int length, int id) {
        byte[] copy = Arrays.copyOf(data, length);
        copy[0] = (byte) ((id >>> 8) & 0xFF);
        copy[1] = (byte) (id & 0xFF);
        return copy;
    }

    public int id() {
        return id;
    }

    public boolean isResponse() {
        return (flags & 0x8000) != 0;
    }

    public int opcode() {
        return (flags >>> 11) & 0x000F;
    }

    public int flags() {
        return flags;
    }

    public int questionCount() {
        return questionCount;
    }

    public int answerCount() {
        return answerCount;
    }

    public int authorityCount() {
        return authorityCount;
    }

    public int additionalCount() {
        return additionalCount;
    }

    public DnsQuestion question() {
        return question;
    }

    private static void writeHeader(ByteArrayOutputStream out, DnsMessage request, int rcode, int answerCount) {
        int responseFlags = 0x8000 | 0x0080 | (request.flags & 0x0100) | (rcode & 0x000F);
        writeShort(out, request.id);
        writeShort(out, responseFlags);
        writeShort(out, 1);
        writeShort(out, answerCount);
        writeShort(out, 0);
        writeShort(out, 0);
    }

    private static void writeQuestion(ByteArrayOutputStream out, DnsMessage request) {
        out.write(request.packet, request.question.startOffset(), request.question.endOffset() - request.question.startOffset());
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}
