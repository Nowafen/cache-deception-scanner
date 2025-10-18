package wcdscanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.ByteArray;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class FilterManager {
    private final PersistedObject extensionData;
    private final DomainTreeManager domainTreeManager;
    private boolean inScope = false;
    private boolean noResponse = false;
    private boolean parameterized = false;
    private boolean html = true;
    private boolean script = true;
    private boolean xml = true;
    private boolean css = true;
    private boolean otherText = true;
    private boolean images = true;
    private boolean flash = false;
    private boolean otherBinary = true;
    private boolean status2xx = true;
    private boolean status3xx = true;
    private boolean status4xx = true;
    private boolean status5xx = true;
    private boolean target = true;
    private boolean proxy = true;
    private boolean scanner = true;
    private boolean intruder = true;
    private boolean repeater = true;
    private boolean sequencer = true;
    private boolean extensions = true;
    private boolean getMethod = true;
    private boolean postMethod = false;
    private boolean putMethod = false;
    private boolean deleteMethod = false;
    private boolean headMethod = false;
    private boolean optionsMethod = false;
    private boolean patchMethod = false;
    private boolean traceMethod = false;
    private String searchText = "";
    private String statusFilter = "All";

    public FilterManager(PersistedObject extensionData, DomainTreeManager domainTreeManager) {
        this.extensionData = extensionData;
        this.domainTreeManager = domainTreeManager;
    }

    public PersistedObject getExtensionData() {
        return extensionData;
    }

    public boolean getGetMethod() { return getMethod; }
    public boolean getPostMethod() { return postMethod; }
    public boolean getPutMethod() { return putMethod; }
    public boolean getDeleteMethod() { return deleteMethod; }
    public boolean getHeadMethod() { return headMethod; }
    public boolean getOptionsMethod() { return optionsMethod; }
    public boolean getPatchMethod() { return patchMethod; }
    public boolean getTraceMethod() { return traceMethod; }

    public boolean applyFilters(HttpRequestResponse response) {
        HttpRequest request = response.request();
        HttpResponse httpResponse = response.response();
        String method = request.method();
        int statusCode = httpResponse != null ? httpResponse.statusCode() : 0;
        String host = request.url().toString().contains("://") ? request.url().toString().split("/")[2].split(":")[0] : "N/A";
        String path = request.url().toString().substring(request.url().toString().indexOf(host) + host.length());
        int length = httpResponse != null ? httpResponse.body().length() : 0;

        if (!searchText.isEmpty() && httpResponse != null) {
            String responseBody = new String(httpResponse.body().getBytes());
            if (!responseBody.contains(searchText)) {
                return false;
            }
        }

        if (!statusFilter.equals("All")) {
            String statusStr = String.valueOf(statusCode).substring(0, 1) + "xx";
            if (!statusFilter.contains(statusStr)) return false;
        }

        if (inScope || noResponse || parameterized) {
            if (noResponse && httpResponse == null) return false;
        }

        String contentType = httpResponse != null ? httpResponse.headers().stream()
                .filter(header -> "Content-Type".equalsIgnoreCase(header.name()))
                .findFirst()
                .map(burp.api.montoya.http.message.HttpHeader::value)
                .orElse("") : "";
        boolean isHtml = contentType.contains("text/html");
        boolean isScript = contentType.contains("application/javascript") || contentType.contains("text/javascript");
        boolean isXml = contentType.contains("application/xml") || contentType.contains("text/xml");
        boolean isCss = contentType.contains("text/css");
        boolean isOtherText = contentType.contains("text/") && !isHtml && !isXml && !isCss;
        boolean isImage = contentType.contains("image/");
        boolean isFlash = contentType.contains("application/x-shockwave-flash");
        boolean isOtherBinary = !contentType.contains("text/") && !isImage && !isFlash;
        if (!html && isHtml) return false;
        if (!script && isScript) return false;
        if (!xml && isXml) return false;
        if (!css && isCss) return false;
        if (!otherText && isOtherText) return false;
        if (!images && isImage) return false;
        if (!flash && isFlash) return false;
        if (!otherBinary && isOtherBinary) return false;

        return true;
    }

    public boolean applyFilters(PacketInfo packetInfo) {
        String method = packetInfo.getMethod();
        int statusCode = packetInfo.getStatusCode();
        String host = packetInfo.getUrl().contains("://") ? packetInfo.getUrl().split("/")[2].split(":")[0] : "N/A";

        if (!searchText.isEmpty()) {
            ByteArray responseBytes = extensionData.getByteArray(packetInfo.getStorageKey() + "_response");
            if (responseBytes != null) {
                String responseBody = new String(responseBytes.getBytes());
                if (!responseBody.contains(searchText)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if (!statusFilter.equals("All")) {
            String statusStr = String.valueOf(statusCode).substring(0, 1) + "xx";
            if (!statusFilter.contains(statusStr)) return false;
        }

        if (inScope || noResponse || parameterized) {
            if (noResponse && extensionData.getByteArray(packetInfo.getStorageKey() + "_response") == null) return false;
        }

        ByteArray responseBytes = extensionData.getByteArray(packetInfo.getStorageKey() + "_response");
        String contentType = "";
        if (responseBytes != null) {
            HttpResponse response = HttpResponse.httpResponse(responseBytes);
            contentType = response.headers().stream()
                    .filter(header -> "Content-Type".equalsIgnoreCase(header.name()))
                    .findFirst()
                    .map(burp.api.montoya.http.message.HttpHeader::value)
                    .orElse("");
        }

        boolean isHtml = contentType.contains("text/html");
        boolean isScript = contentType.contains("application/javascript") || contentType.contains("text/javascript");
        boolean isXml = contentType.contains("application/xml") || contentType.contains("text/xml");
        boolean isCss = contentType.contains("text/css");
        boolean isOtherText = contentType.contains("text/") && !isHtml && !isXml && !isCss;
        boolean isImage = contentType.contains("image/");
        boolean isFlash = contentType.contains("application/x-shockwave-flash");
        boolean isOtherBinary = !contentType.contains("text/") && !isImage && !isFlash;

        if (!html && isHtml) return false;
        if (!script && isScript) return false;
        if (!xml && isXml) return false;
        if (!css && isCss) return false;
        if (!otherText && isOtherText) return false;
        if (!images && isImage) return false;
        if (!flash && isFlash) return false;
        if (!otherBinary && isOtherBinary) return false;

        return true;
    }

    public void showSettingsDialog(JPanel mainPanel, String lastSelectedDomain, Consumer<String> updateLogTableCallback) {
        JDialog dialog = new JDialog((JFrame) SwingUtilities.getWindowAncestor(mainPanel), "Filter Options", true);
        dialog.setSize(900, 400);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setLocationRelativeTo(mainPanel);

        JPanel settingsContentPanel = new JPanel(new GridLayout(2, 3, 10, 5));

        JCheckBox inScopeCheck = new JCheckBox("Show only in-scope items (Suite scope)", inScope);
        JCheckBox noResponseCheck = new JCheckBox("Hide items without responses", noResponse);
        JCheckBox parameterizedCheck = new JCheckBox("Show only parameterized requests", parameterized);

        JPanel requestTypePanel = new JPanel();
        requestTypePanel.setBorder(BorderFactory.createTitledBorder("Filter by request type"));
        requestTypePanel.setLayout(new GridLayout(3, 1));
        requestTypePanel.add(inScopeCheck);
        requestTypePanel.add(noResponseCheck);
        requestTypePanel.add(parameterizedCheck);

        JCheckBox htmlCheck = new JCheckBox("HTML", html);
        JCheckBox scriptCheck = new JCheckBox("Script", script);
        JCheckBox xmlCheck = new JCheckBox("XML", xml);
        JCheckBox cssCheck = new JCheckBox("CSS", css);
        JCheckBox otherTextCheck = new JCheckBox("Other text", otherText);
        JCheckBox imagesCheck = new JCheckBox("Images", images);
        JCheckBox flashCheck = new JCheckBox("Flash", flash);
        JCheckBox otherBinaryCheck = new JCheckBox("Other binary", otherBinary);

        JPanel mimePanel = new JPanel();
        mimePanel.setBorder(BorderFactory.createTitledBorder("Filter by MIME type"));
        mimePanel.setLayout(new GridLayout(4, 2));
        mimePanel.add(htmlCheck);
        mimePanel.add(scriptCheck);
        mimePanel.add(xmlCheck);
        mimePanel.add(cssCheck);
        mimePanel.add(otherTextCheck);
        mimePanel.add(imagesCheck);
        mimePanel.add(flashCheck);
        mimePanel.add(otherBinaryCheck);

        JCheckBox status2xxCheck = new JCheckBox("2xx [success]", status2xx);
        JCheckBox status3xxCheck = new JCheckBox("3xx [redirection]", status3xx);
        JCheckBox status4xxCheck = new JCheckBox("4xx [request error]", status4xx);
        JCheckBox status5xxCheck = new JCheckBox("5xx [server error]", status5xx);

        JPanel statusPanel = new JPanel();
        statusPanel.setBorder(BorderFactory.createTitledBorder("Filter by status code"));
        statusPanel.setLayout(new GridLayout(4, 1));
        statusPanel.add(status2xxCheck);
        statusPanel.add(status3xxCheck);
        statusPanel.add(status4xxCheck);
        statusPanel.add(status5xxCheck);

        JCheckBox targetCheck = new JCheckBox("Target", target);
        JCheckBox proxyCheck = new JCheckBox("Proxy", proxy);
        JCheckBox scannerCheck = new JCheckBox("Scanner", scanner);
        JCheckBox intruderCheck = new JCheckBox("Intruder", intruder);
        JCheckBox repeaterCheck = new JCheckBox("Repeater", repeater);
        JCheckBox sequencerCheck = new JCheckBox("Sequencer", sequencer);
        JCheckBox extensionsCheck = new JCheckBox("Extensions", extensions);

        JPanel toolPanel = new JPanel();
        toolPanel.setBorder(BorderFactory.createTitledBorder("Filter by tool"));
        toolPanel.setLayout(new GridLayout(4, 2));
        toolPanel.add(targetCheck);
        toolPanel.add(proxyCheck);
        toolPanel.add(scannerCheck);
        toolPanel.add(intruderCheck);
        toolPanel.add(repeaterCheck);
        toolPanel.add(sequencerCheck);
        toolPanel.add(extensionsCheck);

        JPanel searchPanel = new JPanel(new BorderLayout());
        searchPanel.setBorder(BorderFactory.createTitledBorder("Filter by search term"));
        JTextField searchField = new JTextField(searchText);
        searchPanel.add(searchField, BorderLayout.SOUTH);

        settingsContentPanel.add(requestTypePanel);
        settingsContentPanel.add(mimePanel);
        settingsContentPanel.add(statusPanel);
        settingsContentPanel.add(toolPanel);
        settingsContentPanel.add(searchPanel);

        JButton applyButton = new JButton("Apply");
        JButton resetButton = new JButton("Reset to Default");

        applyButton.addActionListener(e -> {
            inScope = inScopeCheck.isSelected();
            noResponse = noResponseCheck.isSelected();
            parameterized = parameterizedCheck.isSelected();
            html = htmlCheck.isSelected();
            script = scriptCheck.isSelected();
            xml = xmlCheck.isSelected();
            css = cssCheck.isSelected();
            otherText = otherTextCheck.isSelected();
            images = imagesCheck.isSelected();
            flash = flashCheck.isSelected();
            otherBinary = otherBinaryCheck.isSelected();
            status2xx = status2xxCheck.isSelected();
            status3xx = status3xxCheck.isSelected();
            status4xx = status4xxCheck.isSelected();
            status5xx = status5xxCheck.isSelected();
            target = targetCheck.isSelected();
            proxy = proxyCheck.isSelected();
            scanner = scannerCheck.isSelected();
            intruder = intruderCheck.isSelected();
            repeater = repeaterCheck.isSelected();
            sequencer = sequencerCheck.isSelected();
            extensions = extensionsCheck.isSelected();
            searchText = searchField.getText().trim();
            statusFilter = getStatusFilter(status2xxCheck, status3xxCheck, status4xxCheck, status5xxCheck);
            updateLogTableCallback.accept(lastSelectedDomain);
            dialog.dispose();
        });

        resetButton.addActionListener(e -> {
            inScope = false;
            noResponse = false;
            parameterized = false;
            html = true;
            script = true;
            xml = true;
            css = true;
            otherText = true;
            images = true;
            flash = false;
            otherBinary = true;
            status2xx = true;
            status3xx = true;
            status4xx = true;
            status5xx = true;
            target = true;
            proxy = true;
            scanner = true;
            intruder = true;
            repeater = true;
            sequencer = true;
            extensions = true;
            searchText = "";
            statusFilter = "All";
            updateLogTableCallback.accept(lastSelectedDomain);
            dialog.dispose();
        });

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonsPanel.add(resetButton);
        buttonsPanel.add(applyButton);

        dialog.add(settingsContentPanel, BorderLayout.CENTER);
        dialog.add(buttonsPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    public void showSendSettingsDialog(JPanel mainPanel) {
        JDialog dialog = new JDialog((JFrame) SwingUtilities.getWindowAncestor(mainPanel), "Send Settings", true);
        dialog.setSize(400, 200);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setLocationRelativeTo(mainPanel);

        JPanel settingsPanel = new JPanel();
        settingsPanel.setBorder(BorderFactory.createTitledBorder("Select HTTP Methods"));
        settingsPanel.setLayout(new GridLayout(4, 2, 10, 5));

        JCheckBox getMethodCheck = new JCheckBox("GET", getMethod);
        JCheckBox postMethodCheck = new JCheckBox("POST", postMethod);
        JCheckBox putMethodCheck = new JCheckBox("PUT", putMethod);
        JCheckBox deleteMethodCheck = new JCheckBox("DELETE", deleteMethod);
        JCheckBox headMethodCheck = new JCheckBox("HEAD", headMethod);
        JCheckBox optionsMethodCheck = new JCheckBox("OPTIONS", optionsMethod);
        JCheckBox patchMethodCheck = new JCheckBox("PATCH", patchMethod);
        JCheckBox traceMethodCheck = new JCheckBox("TRACE", traceMethod);

        settingsPanel.add(getMethodCheck);
        settingsPanel.add(postMethodCheck);
        settingsPanel.add(putMethodCheck);
        settingsPanel.add(deleteMethodCheck);
        settingsPanel.add(headMethodCheck);
        settingsPanel.add(optionsMethodCheck);
        settingsPanel.add(patchMethodCheck);
        settingsPanel.add(traceMethodCheck);

        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            if (!(getMethodCheck.isSelected() || postMethodCheck.isSelected() || putMethodCheck.isSelected() ||
                    deleteMethodCheck.isSelected() || headMethodCheck.isSelected() || optionsMethodCheck.isSelected() ||
                    patchMethodCheck.isSelected() || traceMethodCheck.isSelected())) {
                JOptionPane.showMessageDialog(dialog, "At least one method must be selected.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            getMethod = getMethodCheck.isSelected();
            postMethod = postMethodCheck.isSelected();
            putMethod = putMethodCheck.isSelected();
            deleteMethod = deleteMethodCheck.isSelected();
            headMethod = headMethodCheck.isSelected();
            optionsMethod = optionsMethodCheck.isSelected();
            patchMethod = patchMethodCheck.isSelected();
            traceMethod = traceMethodCheck.isSelected();
            dialog.dispose();
        });

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dialog.dispose());

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonsPanel.add(cancelButton);
        buttonsPanel.add(applyButton);

        dialog.add(settingsPanel, BorderLayout.CENTER);
        dialog.add(buttonsPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private String getStatusFilter(JCheckBox status2xx, JCheckBox status3xx, JCheckBox status4xx, JCheckBox status5xx) {
        List<String> activeStatuses = new ArrayList<>();
        if (status2xx.isSelected()) activeStatuses.add("2xx");
        if (status3xx.isSelected()) activeStatuses.add("3xx");
        if (status4xx.isSelected()) activeStatuses.add("4xx");
        if (status5xx.isSelected()) activeStatuses.add("5xx");
        return activeStatuses.isEmpty() ? "All" : String.join(",", activeStatuses);
    }
}
