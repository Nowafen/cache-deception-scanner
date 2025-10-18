package wcdscanner;

public class PacketInfo {
    private final String url;
    private final String method;
    private final String payload;
    private final String originalPath;
    private final int statusCode;
    private final int length;
    private final String time;
    private final String vulnerabilityStatus;
    private final String storageKey;

    public PacketInfo(String url, String method, String payload, String originalPath, int statusCode,
                      int length, String time, String vulnerabilityStatus, String storageKey) {
        this.url = url;
        this.method = method;
        this.payload = payload;
        this.originalPath = originalPath;
        this.statusCode = statusCode;
        this.length = length;
        this.time = time;
        this.vulnerabilityStatus = vulnerabilityStatus;
        this.storageKey = storageKey;
    }

    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public String getPayload() { return payload; }
    public String getOriginalPath() { return originalPath; }
    public int getStatusCode() { return statusCode; }
    public int getLength() { return length; }
    public String getTime() { return time; }
    public String getVulnerabilityStatus() { return vulnerabilityStatus; }
    public String getStorageKey() { return storageKey; }
}
