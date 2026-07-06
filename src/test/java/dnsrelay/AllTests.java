package dnsrelay;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;

public final class AllTests {
    public static void main(String[] args) throws Exception {
        run("normalizesDomainsForCaseAndTrailingDot", AllTests::normalizesDomainsForCaseAndTrailingDot);
        run("parsesSingleQuestionDnsQuery", AllTests::parsesSingleQuestionDnsQuery);
        run("buildsLocalARecordResponse", AllTests::buildsLocalARecordResponse);
        run("buildsMultipleARecordResponse", AllTests::buildsMultipleARecordResponse);
        run("buildsLocalAaaaRecordResponse", AllTests::buildsLocalAaaaRecordResponse);
        run("buildsNxDomainForBlockedDomain", AllTests::buildsNxDomainForBlockedDomain);
        run("loadsLocalDatabaseAndSkipsBadLines", AllTests::loadsLocalDatabaseAndSkipsBadLines);
        run("loadsMultipleIpv4AndIpv6Records", AllTests::loadsMultipleIpv4AndIpv6Records);
        run("reloadsLocalDatabaseAfterFileChange", AllTests::reloadsLocalDatabaseAfterFileChange);
        run("mapsForwardedIdsBackToClientRequests", AllTests::mapsForwardedIdsBackToClientRequests);
        run("rejectsMultipleQuestionPackets", AllTests::rejectsMultipleQuestionPackets);
        run("rejectsCompressedQuestionNames", AllTests::rejectsCompressedQuestionNames);
        run("rejectsInvalidQuestionLabels", AllTests::rejectsInvalidQuestionLabels);
        System.out.println("All tests passed");
    }

    private static void normalizesDomainsForCaseAndTrailingDot() {
        assertEquals("www.example.com", DnsName.normalize(" WWW.Example.COM. "));
        assertEquals("example.com", DnsName.normalize("example.com"));
    }

    private static void parsesSingleQuestionDnsQuery() throws Exception {
        byte[] query = queryPacket(0x1234, "WWW.Example.COM", DnsRecordType.A);

        DnsMessage message = DnsMessage.parse(query, query.length);

        assertEquals(0x1234, message.id());
        assertEquals(false, message.isResponse());
        assertEquals("www.example.com", message.question().name());
        assertEquals(DnsRecordType.A, message.question().type());
        assertEquals(1, message.question().qclass());
    }

    private static void buildsLocalARecordResponse() throws Exception {
        byte[] query = queryPacket(0xBEEF, "local.test", DnsRecordType.A);
        DnsMessage request = DnsMessage.parse(query, query.length);

        byte[] response = DnsMessage.buildAResponse(request, InetAddress.getByName("1.2.3.4"), 120);

        assertUnsignedShortEquals(0xBEEF, response, 0);
        int flags = unsignedShort(response, 2);
        assertTrue((flags & 0x8000) != 0, "response QR bit should be set");
        assertEquals(0, flags & 0x000F);
        assertUnsignedShortEquals(1, response, 4);
        assertUnsignedShortEquals(1, response, 6);
        int answerOffset = query.length;
        assertUnsignedShortEquals(0xC00C, response, answerOffset);
        assertUnsignedShortEquals(1, response, answerOffset + 2);
        assertUnsignedShortEquals(1, response, answerOffset + 4);
        assertEquals(120, unsignedInt(response, answerOffset + 6));
        assertUnsignedShortEquals(4, response, answerOffset + 10);
        assertByteArrayEquals(new byte[] {1, 2, 3, 4}, Arrays.copyOfRange(response, answerOffset + 12, answerOffset + 16));
    }

    private static void buildsMultipleARecordResponse() throws Exception {
        byte[] query = queryPacket(0xBEEF, "multi.test", DnsRecordType.A);
        DnsMessage request = DnsMessage.parse(query, query.length);

        byte[] response = DnsMessage.buildAddressResponse(request, Arrays.asList(
                InetAddress.getByName("1.1.1.1"),
                InetAddress.getByName("1.1.1.2")), DnsRecordType.A, 120);

        assertUnsignedShortEquals(2, response, 6);
        int firstAnswerOffset = query.length;
        int secondAnswerOffset = firstAnswerOffset + 16;
        assertUnsignedShortEquals(1, response, firstAnswerOffset + 2);
        assertByteArrayEquals(new byte[] {1, 1, 1, 1}, Arrays.copyOfRange(response, firstAnswerOffset + 12, firstAnswerOffset + 16));
        assertUnsignedShortEquals(1, response, secondAnswerOffset + 2);
        assertByteArrayEquals(new byte[] {1, 1, 1, 2}, Arrays.copyOfRange(response, secondAnswerOffset + 12, secondAnswerOffset + 16));
    }

    private static void buildsLocalAaaaRecordResponse() throws Exception {
        byte[] query = queryPacket(0xABCD, "ipv6.test", DnsRecordType.AAAA);
        DnsMessage request = DnsMessage.parse(query, query.length);

        byte[] response = DnsMessage.buildAddressResponse(request, Arrays.asList(
                InetAddress.getByName("2001:db8::1")), DnsRecordType.AAAA, 120);

        assertUnsignedShortEquals(0xABCD, response, 0);
        assertUnsignedShortEquals(1, response, 6);
        int answerOffset = query.length;
        assertUnsignedShortEquals(DnsRecordType.AAAA.code(), response, answerOffset + 2);
        assertUnsignedShortEquals(16, response, answerOffset + 10);
    }

    private static void buildsNxDomainForBlockedDomain() throws Exception {
        byte[] query = queryPacket(0xCAFE, "blocked.test", DnsRecordType.A);
        DnsMessage request = DnsMessage.parse(query, query.length);

        byte[] response = DnsMessage.buildNxDomainResponse(request);

        assertUnsignedShortEquals(0xCAFE, response, 0);
        int flags = unsignedShort(response, 2);
        assertTrue((flags & 0x8000) != 0, "response QR bit should be set");
        assertEquals(3, flags & 0x000F);
        assertUnsignedShortEquals(1, response, 4);
        assertUnsignedShortEquals(0, response, 6);
    }

    private static void loadsLocalDatabaseAndSkipsBadLines() throws Exception {
        Path file = Files.createTempFile("dnsrelay-test", ".txt");
        Files.write(file, Arrays.asList(
                "# comment",
                "1.2.3.4 Example.COM.",
                "0.0.0.0 blocked.test",
                "bad-ip bad.example",
                "5.6.7.8",
                "9.9.9.9 valid.test"));
        ByteArrayOutputStream errors = new ByteArrayOutputStream();

        LocalDnsDatabase database = LocalDnsDatabase.load(file, new PrintStream(errors));

        assertEquals("1.2.3.4", require(database.lookup("example.com")).address().getHostAddress());
        assertEquals(true, require(database.lookup("blocked.test")).isBlocked());
        assertEquals("9.9.9.9", require(database.lookup("valid.test")).address().getHostAddress());
        assertEquals(false, database.lookup("bad.example").isPresent());
        assertTrue(errors.toString().contains("Skipping invalid line"), "invalid lines should be reported");
    }

    private static void loadsMultipleIpv4AndIpv6Records() throws Exception {
        Path file = Files.createTempFile("dnsrelay-multi", ".txt");
        Files.write(file, Arrays.asList(
                "1.1.1.1 a.com",
                "1.1.1.2 a.com",
                "2001:db8::1 a.com",
                "2001:db8::2 a.com"));

        LocalDnsDatabase database = LocalDnsDatabase.load(file, System.err);
        LocalDnsDatabase.Entry entry = require(database.lookup("a.com"));

        assertEquals(2, entry.addressesFor(DnsRecordType.A).size());
        assertEquals(2, entry.addressesFor(DnsRecordType.AAAA).size());
    }

    private static void reloadsLocalDatabaseAfterFileChange() throws Exception {
        Path file = Files.createTempFile("dnsrelay-reload", ".txt");
        Files.write(file, Arrays.asList("1.1.1.1 a.com"));
        LocalDnsDatabase database = LocalDnsDatabase.load(file, System.err);
        assertEquals("1.1.1.1", require(database.lookup("a.com")).addressesFor(DnsRecordType.A).get(0).getHostAddress());

        Thread.sleep(5L);
        Files.write(file, Arrays.asList("1.1.1.2 a.com"));
        LocalDnsDatabase reloaded = database.reloadIfChanged(System.err);

        assertEquals("1.1.1.2", require(reloaded.lookup("a.com")).addressesFor(DnsRecordType.A).get(0).getHostAddress());
    }

    private static void mapsForwardedIdsBackToClientRequests() throws Exception {
        IdMapper mapper = new IdMapper();
        InetSocketAddress client = new InetSocketAddress("127.0.0.1", 53000);

        IdMapper.PendingQuery pending = mapper.register(0x1111, client, "www.example.com", DnsRecordType.A.code(), 1);

        assertTrue(pending.forwardedId() >= 0 && pending.forwardedId() <= 0xFFFF, "forwarded id must be 16-bit");
        assertEquals(false, pending.forwardedId() == 0x1111);
        assertEquals(0x1111, require(mapper.remove(pending.forwardedId())).originalId());
        assertEquals(client, pending.client());
        assertEquals("www.example.com", pending.queryName());
        assertEquals(DnsRecordType.A.code(), pending.queryType());
        assertEquals(1, pending.queryClass());
        assertEquals(false, mapper.remove(pending.forwardedId()).isPresent());
    }

    private static void rejectsMultipleQuestionPackets() throws Exception {
        byte[] query = queryPacket(0x2222, "www.example.com", DnsRecordType.A);
        query[5] = 2;

        assertParseFails(query, "exactly one question");
    }

    private static void rejectsCompressedQuestionNames() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShort(out, 0x3333);
        writeShort(out, 0x0100);
        writeShort(out, 1);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0xC00C);
        writeShort(out, DnsRecordType.A.code());
        writeShort(out, 1);

        assertParseFails(out.toByteArray(), "Compressed DNS names");
    }

    private static void rejectsInvalidQuestionLabels() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShort(out, 0x4444);
        writeShort(out, 0x0100);
        writeShort(out, 1);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        byte[] invalidLabel = new byte[] {'b', 'a', 'd', '.'};
        out.write(invalidLabel.length);
        out.write(invalidLabel);
        out.write(0);
        writeShort(out, DnsRecordType.A.code());
        writeShort(out, 1);

        assertParseFails(out.toByteArray(), "non-ASCII DNS character");
    }

    private static byte[] queryPacket(int id, String name, DnsRecordType type) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShort(out, id);
        writeShort(out, 0x0100);
        writeShort(out, 1);
        writeShort(out, 0);
        writeShort(out, 0);
        writeShort(out, 0);
        for (String label : name.split("\\.")) {
            byte[] labelBytes = label.getBytes("US-ASCII");
            out.write(labelBytes.length);
            out.write(labelBytes);
        }
        out.write(0);
        writeShort(out, type.code());
        writeShort(out, 1);
        return out.toByteArray();
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int unsignedInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private static void assertUnsignedShortEquals(int expected, byte[] data, int offset) {
        assertEquals(expected, unsignedShort(data, offset));
    }

    private static void assertByteArrayEquals(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Expected " + Arrays.toString(expected) + " but was " + Arrays.toString(actual));
        }
    }

    private static void run(String name, ThrowingRunnable test) throws Exception {
        try {
            test.run();
            System.out.println("PASS " + name);
        } catch (Throwable error) {
            System.err.println("FAIL " + name);
            throw error;
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected " + expected + " but was " + actual);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertParseFails(byte[] packet, String expectedMessagePart) throws Exception {
        try {
            DnsMessage.parse(packet, packet.length);
        } catch (DnsParseException ex) {
            assertTrue(ex.getMessage().contains(expectedMessagePart),
                    "Expected parse failure containing " + expectedMessagePart + " but was " + ex.getMessage());
            return;
        }
        throw new AssertionError("Expected DNS parse failure");
    }

    private static <T> T require(Optional<T> optional) {
        if (!optional.isPresent()) {
            throw new AssertionError("Expected optional value to be present");
        }
        return optional.get();
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
