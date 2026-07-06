public final class dnsrelay {
    private dnsrelay() {
    }

    public static void main(String[] args) throws Exception {
        Class<?> mainClass = Class.forName("dnsrelay.DnsRelay");
        mainClass.getMethod("main", String[].class).invoke(null, (Object) args);
    }
}
