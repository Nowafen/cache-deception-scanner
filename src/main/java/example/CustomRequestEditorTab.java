package example.customrequesteditortab;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.*;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import burp.api.montoya.persistence.PersistedObject;

class PacketInfo {
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

/**
 * Main class for the WCD Scanner Burp extension.
 */
public class CustomRequestEditorTab implements BurpExtension {
    private ExecutorService executorService;
    private MontoyaApi api;
    private JPanel mainPanel;
    private JTree domainTree;
    private DefaultTreeModel domainTreeModel;
    private DefaultMutableTreeNode rootNode;
    private Map<String, Set<String>> domainTreeData = new HashMap<>();
    private JTable logTable;
    private DefaultTableModel logModel;
    private List<PacketInfo> packetList = new ArrayList<>();
    private RawEditor requestEditor, responseEditor;
    private JSplitPane detailPane;
    private HttpRequestResponse requestResponse;
    private Map<String, List<PacketInfo>> domainPackets = new HashMap<>();
    private JPanel domainPanel;
    private String searchText = "";
    private String statusFilter = "All";
    private String lastSelectedDomain = null;
    private TableRowSorter<DefaultTableModel> sorter;
    private Map<String, Integer> domainPacketCounters = new HashMap<>(); 
    private boolean reverseOrder = false;
    private JTabbedPane domainTabbedPane;
    private Map<String, String> payloadMap = new HashMap<>(); 


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
    private PersistedObject extensionData;
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

    /**
     * Initializes the Burp extension with the Montoya API.
     * @param api The Montoya API instance provided by Burp.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.executorService = Executors.newFixedThreadPool(5); 
        this.extensionData = api.persistence().extensionData();
        api.extension().setName("WCD Scanner");

        
        api.extension().registerUnloadingHandler(() -> {
            try {
                executorService.shutdown(); 
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    executorService.shutdownNow(); 
                    api.logging().logToOutput("Some threads did not terminate in time during unload.");
                }
                api.logging().logToOutput("Extension unloaded successfully, all threads terminated.");
            } catch (InterruptedException e) {
                api.logging().logToError("Error during extension unload: " + e.getMessage());
            }
        });

        api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProvider(api));

        mainPanel = new JPanel(new BorderLayout());
        setupUI();

        api.userInterface().registerSuiteTab("WCD Scanner", mainPanel);
        api.userInterface().registerContextMenuItemsProvider(new MyContextMenuItemsProvider(this));
    }

    /**
     * Refreshes the domain tree by adding only the base domains with a root icon.
     */
    private void refreshDomainTree() {
        rootNode.removeAllChildren();

        for (String domain : domainTreeData.keySet()) {
            DefaultMutableTreeNode domainNode = new DefaultMutableTreeNode(new DomainNode(domain, true));
            rootNode.add(domainNode);
        }

        domainTreeModel.reload();
    }

    /**
     * Expands the domain tree to show subdomains for a given domain.
     * @param domain The base domain to expand.
     */
    private void expandDomainTree(String domain) {
        DefaultMutableTreeNode domainNode = null;
        for (int i = 0; i < rootNode.getChildCount(); i++) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) rootNode.getChildAt(i);
            if (node.toString().equals(domain)) {
                domainNode = node;
                break;
            }
        }

        if (domainNode != null) {
            domainNode.removeAllChildren();
            Set<String> subdomains = domainTreeData.get(domain);
            if (subdomains != null) {
                for (String subdomain : subdomains) {
                    domainNode.add(new DefaultMutableTreeNode(new DomainNode(subdomain, false)));
                }
            }
            domainTreeModel.reload(domainNode);
            domainTree.expandPath(new TreePath(domainNode.getPath()));
        }
    }

    /**
     * Expands all nodes in the given JTree.
     * @param tree The JTree to expand.
     */
    private void expandAllTreeNodes(JTree tree) {
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    /**
     * Sets up the UI components for the extension tab.
     */
    private void setupUI() {
        domainPanel = new JPanel(new BorderLayout());
        domainTabbedPane = new JTabbedPane();
        domainTabbedPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        rootNode = new DefaultMutableTreeNode("Domains");
        domainTreeModel = new DefaultTreeModel(rootNode);
        domainTree = new JTree(domainTreeModel);
        domainTree.setRootVisible(false);
        domainTree.setShowsRootHandles(true);
        domainTree.setRowHeight(24);
        domainTree.setCellRenderer(new CustomTreeCellRenderer());

        domainTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                TreePath path = domainTree.getPathForLocation(e.getX(), e.getY());
                if (path != null) {
                    DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) path.getLastPathComponent();
                    if (selectedNode != null && !selectedNode.isRoot()) {
                        DomainNode nodeData = (DomainNode) selectedNode.getUserObject();
                        String selectedDomain = nodeData.getDomain();
                        if (e.getClickCount() == 2) {
                            showDomainActionsTab(selectedDomain);
                        } else if (e.getClickCount() == 1) {
                            if (nodeData.isRoot()) {
                                expandDomainTree(selectedDomain);
                            }
                            lastSelectedDomain = selectedDomain;
                            updateLogTableForDomain(selectedDomain);
                        }
                    }
                }
            }
        });

        JScrollPane domainTreeScrollPane = new JScrollPane(domainTree);
        domainTreeScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JPanel domainTabPanel = new JPanel(new BorderLayout());
        domainTabPanel.add(domainTreeScrollPane, BorderLayout.CENTER);

        domainTabbedPane.addTab("Domains", domainTabPanel);
        domainPanel.add(domainTabbedPane, BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logModel = new DefaultTableModel(
            new Object[][]{},
            new Object[]{"ID", "Host", "Path", "Method", "Status Code", "Length", "Payload", "Time", "Vulnerable"}
        ) {
            Class<?>[] columnTypes = new Class<?>[] {
                Integer.class, String.class, String.class, String.class, Integer.class, Integer.class, String.class, String.class, String.class
            };
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnTypes[columnIndex];
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; 
            }
        };
        logTable = new JTable(logModel);
        logTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        logTable.setFillsViewportHeight(true);
        logTable.setDefaultEditor(Object.class, null); 

        TableCellRenderer leftRenderer = new DefaultTableCellRenderer() {
            {
                setHorizontalAlignment(JLabel.LEFT);
            }
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 0 || column == 4 || column == 5) {
                    ((JLabel) c).setHorizontalAlignment(JLabel.LEFT);
                }
                return c;
            }
        };
        logTable.getColumnModel().getColumn(0).setCellRenderer(leftRenderer);
        logTable.getColumnModel().getColumn(4).setCellRenderer(leftRenderer);
        logTable.getColumnModel().getColumn(5).setCellRenderer(leftRenderer);
        logTable.getColumnModel().getColumn(8).setCellRenderer(new VulnerabilityRenderer());

        sorter = new TableRowSorter<>(logModel);
        logTable.setRowSorter(sorter);
        sorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.ASCENDING)));

        for (int i = 0; i < logTable.getColumnCount(); i++) {
            int preferredWidth = 100;
            String columnName = logTable.getColumnName(i);
            switch (columnName) {
                case "ID": preferredWidth = 80; break;
                case "Host": preferredWidth = 400; break;
                case "Path": preferredWidth = 400; break;
                case "Method": preferredWidth = 100; break;
                case "Status Code": preferredWidth = 100; break;
                case "Length": preferredWidth = 150; break;
                case "Payload": preferredWidth = 250; break;
                case "Time": preferredWidth = 200; break;
                case "Vulnerable": preferredWidth = 250; break;
            }
            logTable.getColumnModel().getColumn(i).setPreferredWidth(preferredWidth);
        }

        JScrollPane logScrollPane = new JScrollPane(logTable);
        logPanel.add(logScrollPane, BorderLayout.CENTER);

        JPanel settingsFilterPanel = createSettingsFilterPanel(this::showSettingsDialog);
        JPanel sendSettingsPanel = createSendSettingsPanel(this::showSendSettingsDialog);

        requestEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.add(new JLabel("Request", JLabel.CENTER), BorderLayout.NORTH);
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.add(new JLabel("Response", JLabel.CENTER), BorderLayout.NORTH);
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        requestResponseSplitPane.setDividerLocation(0.5);
        requestResponseSplitPane.setResizeWeight(0.5);
        requestResponseSplitPane.setOneTouchExpandable(true);
        requestResponseSplitPane.setDividerSize(10);

        detailPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, logPanel, requestResponseSplitPane);
        detailPane.setDividerLocation(0.5);
        detailPane.setResizeWeight(0.5);
        detailPane.setOneTouchExpandable(true);
        detailPane.setDividerSize(10);
        detailPane.addPropertyChangeListener("dividerLocation", evt -> {
            int maxHeight = (int) (mainPanel.getHeight() * 0.5);
            if ((int) evt.getNewValue() > maxHeight) {
                detailPane.setDividerLocation(maxHeight);
            }
        });

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, domainPanel, detailPane);
        mainSplitPane.setDividerLocation(250);
        mainSplitPane.setResizeWeight(0.4);
        mainSplitPane.setContinuousLayout(true);
        mainSplitPane.setOneTouchExpandable(true);
        mainSplitPane.setDividerSize(10);
        mainSplitPane.addPropertyChangeListener("dividerLocation", evt -> {
            int maxWidth = (int) (mainPanel.getWidth() * 0.4);
            if ((int) evt.getNewValue() > maxWidth) {
                mainSplitPane.setDividerLocation(maxWidth);
            }
        });

        JPanel topFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        topFilterPanel.add(settingsFilterPanel);
        topFilterPanel.add(sendSettingsPanel);

        mainPanel.add(topFilterPanel, BorderLayout.NORTH);
        mainPanel.add(mainSplitPane, BorderLayout.CENTER);

        logTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && logTable.getSelectedRow() != -1) {
                int row = logTable.convertRowIndexToModel(logTable.getSelectedRow());
                showPacketDetails(row);
            }
        });
    }

    /**
     * Creates a settings filter panel with a rounded border and click event.
     */
    private JPanel createSettingsFilterPanel(Runnable onClick) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        panel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        panel.setMaximumSize(new Dimension(1500, 35));
        panel.setPreferredSize(new Dimension(1500, 35));

        JLabel iconLabel = new JLabel("\u2699"); // ⚙️
        iconLabel.setForeground(new Color(200, 200, 200));
        iconLabel.setFont(new Font("Segoe UI", Font.PLAIN, 20));

        JLabel textLabel = new JLabel("Filter settings: Showing in-scope and parameterized requests; hiding responses by MIME type or status code; filtering by tool and search term");
        textLabel.setForeground(new Color(200, 200, 200));
        textLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        textLabel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));

        panel.add(iconLabel);
        panel.add(textLabel);

        panel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                panel.setBackground(new Color(55, 55, 55));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                panel.setBackground(new Color(43, 43, 43));
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onClick != null) onClick.run();
            }
        });

        return panel;
    }

    /**
     * Creates a send settings panel with a rounded border and click event.
     */
    private JPanel createSendSettingsPanel(Runnable onClick) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        panel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        panel.setMaximumSize(new Dimension(200, 35));
        panel.setPreferredSize(new Dimension(200, 35));

        JLabel iconLabel = new JLabel("\u27A4"); // ➤
        iconLabel.setForeground(new Color(200, 200, 200));
        iconLabel.setFont(new Font("Segoe UI", Font.PLAIN, 20));

        JLabel textLabel = new JLabel(" Send Settings");
        textLabel.setForeground(new Color(200, 200, 200));
        textLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        textLabel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));

        panel.add(iconLabel);
        panel.add(textLabel);

        panel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                panel.setBackground(new Color(55, 55, 55));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                panel.setBackground(new Color(43, 43, 43));
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onClick != null) onClick.run();
            }
        });

        return panel;
    }

    /**
     * Shows a dialog for domain actions with a delete button.
     */
    private void showDomainActionsTab(String selectedDomain) {
        for (int i = domainTabbedPane.getTabCount() - 1; i > 0; i--) {
            domainTabbedPane.removeTabAt(i);
        }

        JPanel actionsPanel = new JPanel(new BorderLayout());
        actionsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel domainLabel = new JLabel("Actions for: " + selectedDomain);
        domainLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        actionsPanel.add(domainLabel, BorderLayout.NORTH);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton deleteButton = new JButton("Delete Packets");
        deleteButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                mainPanel,
                "Are you sure you want to delete all packets for " + selectedDomain + "?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
                deleteSubdomainPackets(selectedDomain);
                domainTabbedPane.remove(actionsPanel);
                domainTabbedPane.setSelectedIndex(0);
            }
        });
        buttonPanel.add(deleteButton);
        actionsPanel.add(buttonPanel, BorderLayout.CENTER);

        domainTabbedPane.addTab("Domain Actions", actionsPanel);
        domainTabbedPane.setSelectedIndex(domainTabbedPane.getTabCount() - 1);
    }

    /**
     * Deletes all packets for a subdomain and removes it from the tree.
     */
    private void deleteSubdomainPackets(String subdomain) {
        List<PacketInfo> packets = domainPackets.remove(subdomain);
        if (packets != null) {
            for (PacketInfo packet : packets) {
                extensionData.deleteByteArray(packet.getStorageKey() + "_request");
                extensionData.deleteByteArray(packet.getStorageKey() + "_response");
            }
        }
        packetList.removeIf(p -> {
            String url = p.getUrl();
            String host = url.contains("://") ? url.split("/")[2].split(":")[0] : "N/A";
            return host.equals(subdomain);
        });

        String baseDomain = extractBaseDomain(subdomain);
        Set<String> subdomains = domainTreeData.get(baseDomain);
        if (subdomains != null) {
            subdomains.remove(subdomain);
            if (subdomains.isEmpty()) {
                domainTreeData.remove(baseDomain);
            }
        }

        if (lastSelectedDomain != null && lastSelectedDomain.equals(subdomain)) {
            lastSelectedDomain = null;
            updateLogTableForDomain(null);
        }

        refreshDomainTree();
    }

    private static class RoundedBorder extends AbstractBorder {
        private final int radius;

        public RoundedBorder(int radius) {
            this.radius = radius;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(new Color(90, 90, 90));
            g2.drawRoundRect(x, y, width - 1, height - 1, radius, radius);
        }

        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(radius + 1, radius + 1, radius + 1, radius + 1);
        }

        @Override
        public Insets getBorderInsets(Component c, Insets insets) {
            insets.set(radius + 1, radius + 1, radius + 1, radius + 1);
            return insets;
        }
    }

    /**
     * Shows a dialog for filter settings.
     */
    private void showSettingsDialog() {
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

        JCheckBox html = new JCheckBox("HTML", this.html);
        JCheckBox script = new JCheckBox("Script", this.script);
        JCheckBox xml = new JCheckBox("XML", this.xml);
        JCheckBox css = new JCheckBox("CSS", this.css);
        JCheckBox otherText = new JCheckBox("Other text", this.otherText);
        JCheckBox images = new JCheckBox("Images", this.images);
        JCheckBox flash = new JCheckBox("Flash", this.flash);
        JCheckBox otherBinary = new JCheckBox("Other binary", this.otherBinary);

        JPanel mimePanel = new JPanel();
        mimePanel.setBorder(BorderFactory.createTitledBorder("Filter by MIME type"));
        mimePanel.setLayout(new GridLayout(4, 2));
        mimePanel.add(html);
        mimePanel.add(script);
        mimePanel.add(xml);
        mimePanel.add(css);
        mimePanel.add(otherText);
        mimePanel.add(images);
        mimePanel.add(flash);
        mimePanel.add(otherBinary);

        JCheckBox status2xx = new JCheckBox("2xx [success]", this.status2xx);
        JCheckBox status3xx = new JCheckBox("3xx [redirection]", this.status3xx);
        JCheckBox status4xx = new JCheckBox("4xx [request error]", this.status4xx);
        JCheckBox status5xx = new JCheckBox("5xx [server error]", this.status5xx);

        JPanel statusPanel = new JPanel();
        statusPanel.setBorder(BorderFactory.createTitledBorder("Filter by status code"));
        statusPanel.setLayout(new GridLayout(4, 1));
        statusPanel.add(status2xx);
        statusPanel.add(status3xx);
        statusPanel.add(status4xx);
        statusPanel.add(status5xx);

        JCheckBox target = new JCheckBox("Target", this.target);
        JCheckBox proxy = new JCheckBox("Proxy", this.proxy);
        JCheckBox scanner = new JCheckBox("Scanner", this.scanner);
        JCheckBox intruder = new JCheckBox("Intruder", this.intruder);
        JCheckBox repeater = new JCheckBox("Repeater", this.repeater);
        JCheckBox sequencer = new JCheckBox("Sequencer", this.sequencer);
        JCheckBox extensions = new JCheckBox("Extensions", this.extensions);

        JPanel toolPanel = new JPanel();
        toolPanel.setBorder(BorderFactory.createTitledBorder("Filter by tool"));
        toolPanel.setLayout(new GridLayout(4, 2));
        toolPanel.add(target);
        toolPanel.add(proxy);
        toolPanel.add(scanner);
        toolPanel.add(intruder);
        toolPanel.add(repeater);
        toolPanel.add(sequencer);
        toolPanel.add(extensions);

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
            this.html = html.isSelected();
            this.script = script.isSelected();
            this.xml = xml.isSelected();
            this.css = css.isSelected();
            this.otherText = otherText.isSelected();
            this.images = images.isSelected();
            this.flash = flash.isSelected();
            this.otherBinary = otherBinary.isSelected();
            this.status2xx = status2xx.isSelected();
            this.status3xx = status3xx.isSelected();
            this.status4xx = status4xx.isSelected();
            this.status5xx = status5xx.isSelected();
            this.target = target.isSelected();
            this.proxy = proxy.isSelected();
            this.scanner = scanner.isSelected();
            this.intruder = intruder.isSelected();
            this.repeater = repeater.isSelected();
            this.sequencer = sequencer.isSelected();
            this.extensions = extensions.isSelected();
            searchText = searchField.getText().trim();
            statusFilter = getStatusFilter(status2xx, status3xx, status4xx, status5xx);
            updateLogTableForDomain(lastSelectedDomain);
            dialog.dispose();
        });

        resetButton.addActionListener(e -> {
            inScope = false;
            noResponse = false;
            parameterized = false;
            this.html = true;
            this.script = true;
            this.xml = true;
            this.css = true;
            this.otherText = true;
            this.images = true;
            this.flash = false;
            this.otherBinary = true;
            this.status2xx = true;
            this.status3xx = true;
            this.status4xx = true;
            this.status5xx = true;
            this.target = true;
            this.proxy = true;
            this.scanner = true;
            this.intruder = true;
            this.repeater = true;
            this.sequencer = true;
            this.extensions = true;
            searchText = "";
            statusFilter = "All";
            updateLogTableForDomain(lastSelectedDomain);
            dialog.dispose();
        });

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonsPanel.add(resetButton);
        buttonsPanel.add(applyButton);

        dialog.add(settingsContentPanel, BorderLayout.CENTER);
        dialog.add(buttonsPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    /**
     * Shows a dialog for send settings.
     */
    private void showSendSettingsDialog() {
        JDialog dialog = new JDialog((JFrame) SwingUtilities.getWindowAncestor(mainPanel), "Send Settings", true);
        dialog.setSize(400, 200);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setLocationRelativeTo(mainPanel);

        JPanel settingsPanel = new JPanel();
        settingsPanel.setBorder(BorderFactory.createTitledBorder("Select HTTP Methods"));
        settingsPanel.setLayout(new GridLayout(4, 2, 10, 5));

        JCheckBox getMethodCheck = new JCheckBox("GET", this.getMethod);
        JCheckBox postMethodCheck = new JCheckBox("POST", this.postMethod);
        JCheckBox putMethodCheck = new JCheckBox("PUT", this.putMethod);
        JCheckBox deleteMethodCheck = new JCheckBox("DELETE", this.deleteMethod);
        JCheckBox headMethodCheck = new JCheckBox("HEAD", this.headMethod);
        JCheckBox optionsMethodCheck = new JCheckBox("OPTIONS", this.optionsMethod);
        JCheckBox patchMethodCheck = new JCheckBox("PATCH", this.patchMethod);
        JCheckBox traceMethodCheck = new JCheckBox("TRACE", this.traceMethod);

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
            this.getMethod = getMethodCheck.isSelected();
            this.postMethod = postMethodCheck.isSelected();
            this.putMethod = putMethodCheck.isSelected();
            this.deleteMethod = deleteMethodCheck.isSelected();
            this.headMethod = headMethodCheck.isSelected();
            this.optionsMethod = optionsMethodCheck.isSelected();
            this.patchMethod = patchMethodCheck.isSelected();
            this.traceMethod = traceMethodCheck.isSelected();
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

    /**
     * Gets the active status filter based on checkbox selections.
     */
    private String getStatusFilter(JCheckBox status2xx, JCheckBox status3xx, JCheckBox status4xx, JCheckBox status5xx) {
        List<String> activeStatuses = new ArrayList<>();
        if (status2xx.isSelected()) activeStatuses.add("2xx");
        if (status3xx.isSelected()) activeStatuses.add("3xx");
        if (status4xx.isSelected()) activeStatuses.add("4xx");
        if (status5xx.isSelected()) activeStatuses.add("5xx");
        return activeStatuses.isEmpty() ? "All" : String.join(",", activeStatuses);
    }

    /**
     * Applies all filters to a packet and determines if it should be displayed.
     */
    private boolean applyFilters(HttpRequestResponse response) {
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
            .map(HttpHeader::value)
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


    private boolean applyFilters(PacketInfo packetInfo) {
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
                .map(HttpHeader::value)
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

    /**
     * Adds a packet to the extension and performs fuzzing.
     */
    public void addPacket(HttpRequestResponse requestResponse) {
        setTabColor(Color.ORANGE);
        Logging logging = api.logging();
        String[] payloads = {
            
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
            

            "/resource/../../../MainPath/;.js",
            "/resources/..%2fmy-account?wcd",
            "/js/../../MainPath?abcd.css",
            "/resource/_/../../MainPath/js;main.js",
            "/resources/..%2fMainPath",
            "/resources/..%2f..%2fMainPath",
            "/resources/%2e%2e%2fMainPath",
            "/resources/%2e%2e/MainPath",
            "/resources/%2e%2e//MainPath",
            "/resources/..%252fMainPath",
            "/resources/..%c0%afMainPath",
            "/resources/..%5cMainPath",
            "/resources/%2e%2e\\MainPath",
            "/resources/..;/MainPath",
            "/resources/.%2e/MainPath",
            "/resources/%252e%252e%252fMainPath",
            "/resources/%ef%bc%8f../MainPath",
            "/resources/MainPath%00.js",
            "/resources/MainPath.js?",
            "/resources/MainPath.js?fake=1",
            "/resources/MainPath.js#.",
            "/resources/MainPath.js/.",
            "/resources/.js/../MainPath",
            "/resources/.css/../MainPath",
            "/static/..%2fMainPath",
            "/static/%2e%2e/%2e%2e/MainPath",
            "/static/..;/MainPath",
            "/static/..%2f..%2fMainPath",
            "/static/..%5c..%5cMainPath",
            "/static/%2e%2e%5cMainPath",
            "/assets/..%2fMainPath",
            "/assets/%2e%2e/%2e%2e/MainPath",
            "/assets/..;/MainPath",
            "/assets/..%5cMainPath",
            "/assets/%2e%2e%2fMainPath.js",
            "/assets/.js/../MainPath",
            "/assets/..%2fMainPath?cache=1",
            "/public/..%2fMainPath",
            "/public/%2e%2e/%2e%2e/MainPath",
            "/public/..;/MainPath",
            "/public/.js/../MainPath",
            "/public/..%2fMainPath.js",
            "/cdn/..%2fMainPath",
            "/cdn/%2e%2e/%2e%2e/MainPath",
            "/cdn/..;/MainPath",
            "/cdn/.js/../MainPath",
            "/cdn/..%2fMainPath.js?version=1.2.3",
            "/resources/%2e%2e/%2e%2e/%2e%2e/MainPath",
            "/resources/..%2f..%2f..%2fMainPath",
            "/resources///../MainPath",
            "/resources/..//MainPath",
            "/resources/%2e%2e/./MainPath",
            "/resources/%2e%2e%2f./MainPath",
            "/resources/%2e%2e%2fMainPath?wcd",
            "/resources/%2e%2e%2fMainPath?static=true",
            "/resources/%2e%2e%2fMainPath&forcecache=1",
            "/resources/%2e%2e%2fMainPath#static",
            "/resources/%2e%2e%2fMainPath.js&nocache=false",
            "/resources/%2e%2e%2fMainPath.js?v=9999",
            "/resources/%2e%2e%2fMainPath.css",
            "/resources/%2e%2e%2fMainPath.png",
            "/resources/%2e%2e%2fMainPath.jpg",
            "/resources/%2e%2e%2fMainPath.svg",
            "/resources/%2e%2e%2fMainPath.txt",
            "/static/../MainPath",
            "/assets/../MainPath",
            "/public/../MainPath",
            "/cdn/../MainPath"
        };
        HttpRequest originalRequest = requestResponse.request();
        String urlStr = originalRequest.url().toString();
        String host = urlStr.contains("://") ? urlStr.split("/")[2].split(":")[0] : "N/A";
        String domain = extractBaseDomain(host);
        String tempFullHost = host;

        try {
            URI uri = URI.create(originalRequest.url().toString());
            String actualHost = uri.toURL().getHost();
            if (actualHost != null && !actualHost.isEmpty()) {
                tempFullHost = actualHost;
            }

            
            domainTreeData.computeIfAbsent(domain, k -> new LinkedHashSet<>());

            
            if (!tempFullHost.equalsIgnoreCase(domain)) {
                domainTreeData.get(domain).add(tempFullHost);
            }

        } catch (Exception e) {
            api.logging().logToError("✘ URL parse error: " + originalRequest.url().toString());
        }

        final String finalFullHost = tempFullHost;

        SwingUtilities.invokeLater(() -> refreshDomainTree());

        byte[] originalBytes = originalRequest.toByteArray().getBytes();
        String requestFullStr = new String(originalBytes);
        String originalPath = originalRequest.path();

        logging.logToOutput(requestFullStr);

        final MontoyaApi apiInstance = this.api;
        executorService.submit(() -> {
            Logging threadLogging = apiInstance.logging();
            threadLogging.logToOutput("[Thread] Starting fuzzing process for domain: " + domain);

            if (apiInstance.http() == null) {
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
            boolean[] methodEnabled = {getMethod, postMethod, putMethod, deleteMethod, headMethod, optionsMethod, patchMethod, traceMethod};

            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

            for (int i = 0; i < methods.length; i++) {
                final int finalI = i;
                if (methodEnabled[finalI]) {
                    for (String payload : payloads) {
                        String newPath;
                        if (payload.contains("MainPath")) {
                            newPath = payload.replace("MainPath", originalPath.startsWith("/") ? originalPath.substring(1) : originalPath);
                        } else {
                            newPath = originalPath + payload;
                        }
                        String newRequestLine = methods[finalI] + " " + newPath + " " + httpVersion;
                        String fullFuzzedRequest = newRequestLine + restOfRequest;

                        threadLogging.logToOutput(fullFuzzedRequest);

                        try {
                            HttpRequest fuzzedRequest = HttpRequest.httpRequest(httpService, ByteArray.byteArray(fullFuzzedRequest.getBytes()));
                            HttpRequestResponse fuzzedResponse = apiInstance.http().sendRequest(fuzzedRequest);

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
                                    packetList.add(packetInfo);
                                    domainPackets.computeIfAbsent(finalFullHost, k -> new ArrayList<>()).add(packetInfo);
                                    if (lastSelectedDomain != null && lastSelectedDomain.equals(finalFullHost)) {
                                        updateLogTable(packetInfo);
                                        int row = logModel.getRowCount() - 1;
                                        if (row >= 0) {
                                            logTable.setRowSelectionInterval(row, row);
                                            showPacketDetails(row);
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

    

    /**
     * Sets the tab color temporarily.
     */
    private void setTabColor(Color color) {
        SwingUtilities.invokeLater(() -> {
            Component parent = mainPanel.getParent();
            if (parent instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) parent;
                int tabIndex = -1;
                for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                    if (tabbedPane.getComponentAt(i) == mainPanel) {
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

    /**
     * Extracts the base domain from a given host.
     */
    private String extractBaseDomain(String host) {
        String[] parts = host.split("\\.");
        if (parts.length > 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }


    /**
     * Updates the log table with a new response, payload, and method.
     */
    private void updateLogTable(PacketInfo packetInfo) {
        if (applyFilters(packetInfo) && lastSelectedDomain != null && 
            isSubdomainOrSame(lastSelectedDomain, packetInfo.getUrl().contains("://") ? 
            packetInfo.getUrl().split("/")[2].split(":")[0] : "N/A")) {
            int domainCounter = domainPacketCounters.computeIfAbsent(lastSelectedDomain, k -> 1);
            logModel.addRow(new Object[]{
                domainCounter,
                packetInfo.getUrl().contains("://") ? packetInfo.getUrl().split("/")[2].split(":")[0] : "N/A",
                packetInfo.getOriginalPath(), 
                packetInfo.getMethod(),
                packetInfo.getStatusCode(),
                packetInfo.getLength(),
                packetInfo.getPayload(),
                packetInfo.getTime(),
                packetInfo.getVulnerabilityStatus()
            });
            domainPacketCounters.put(lastSelectedDomain, domainCounter + 1);
        }
    }


    /**
     * Updates the log table for a specific domain, including its subdomains.
     */
    private void updateLogTableForDomain(String domain) {
        logModel.setRowCount(0);
        if (domain == null) {
            logTable.setVisible(false);
            return;
        }
        logTable.setVisible(true);
        domainPacketCounters.put(domain, 1);

        List<PacketInfo> allPackets = domainPackets.getOrDefault(domain, new ArrayList<>());

        for (PacketInfo packetInfo : allPackets) {
            if (applyFilters(packetInfo)) {
                updateLogTable(packetInfo);
            }
        }
    }

    

    /**
     * Checks if a host is a subdomain of the given domain or the same.
     */
    private boolean isSubdomainOrSame(String domain, String host) {
        if (host.equals(domain)) return true;
        String baseDomain = extractBaseDomain(host);
        return baseDomain.equals(domain);
    }

    /**
     * Calculates the effective payload by subtracting the original path from the test path.
     */
    private String calculateEffectivePayload(String originalPath, String testPath, String defaultPayload) {
        if (testPath != null && originalPath != null && testPath.startsWith(originalPath)) {
            String effectivePayload = testPath.substring(originalPath.length());
            return effectivePayload.isEmpty() ? defaultPayload : effectivePayload;
        }
        return defaultPayload;
    }

    /**
     * Determines the vulnerability status based on response headers and status code.
     */
    private String getVulnerabilityStatus(HttpResponse response, int statusCode) {
        if (response == null || statusCode != 200) return "Not vulnerable";

        List<HttpHeader> headers = response.headers();
        boolean isCacheEnabled = false;
        boolean isCacheBlocked = false;

        for (HttpHeader header : headers) {
            String name = header.name().toLowerCase();
            String value = header.value().toLowerCase();

            if ("cache-control".equals(name)) {
                if (value.contains("no-store") || value.contains("no-cache") || value.contains("max-age=0") || value.contains("private")) {
                    isCacheBlocked = true;
                } else if (value.contains("max-age") || value.contains("s-maxage") || value.contains("public") ||
                           value.contains("immutable") || value.contains("stale-while-revalidate") ||
                           value.contains("stale-if-error") || value.contains("must-revalidate") ||
                           value.contains("proxy-revalidate") || value.contains("no-transform")) {
                    isCacheEnabled = true;
                }
            } else if ("expires".equals(name)) {
                try {
                    ZonedDateTime expiresDate = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
                    ZonedDateTime now = ZonedDateTime.now();
                    if (expiresDate.isAfter(now)) {
                        isCacheEnabled = true;
                    }
                } catch (Exception e) {
                    // Ignore invalid date formats
                }
            } else if ("etag".equals(name) && !value.isEmpty()) {
                isCacheEnabled = true;
            } else if ("last-modified".equals(name) && !value.isEmpty()) {
                isCacheEnabled = true;
            } else if ("age".equals(name) && !value.isEmpty()) {
                isCacheEnabled = true;
            } else if ("vary".equals(name) && !value.isEmpty()) {
                isCacheEnabled = true;
            } else if ("cache-status".equals(name) && (value.contains("hit") || value.contains("miss"))) {
                isCacheEnabled = true;
            } else if ("pragma".equals(name) && value.contains("no-cache")) {
                isCacheBlocked = true;
            }
        }

        if (isCacheEnabled && !isCacheBlocked) {
            return "vulnerable packet";
        } else if (isCacheBlocked) {
            return "Not vulnerable";
        } else {
            return "Not vulnerable";
        }
    }

    /**
     * Custom renderer for vulnerability status with colored text.
     */
    private class VulnerabilityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value != null) {
                if ("vulnerable packet".equals(value.toString())) {
                    c.setForeground(Color.GREEN);
                } else {
                    c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    private class MyHttpRequestEditorProvider implements HttpRequestEditorProvider {
        private final MontoyaApi api;

        public MyHttpRequestEditorProvider(MontoyaApi api) {
            this.api = api;
        }

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
            return new MyExtensionProvidedHttpRequestEditor();
        }
    }

    private class MyExtensionProvidedHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final RawEditor requestEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        private final RawEditor responseEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        private HttpRequestResponse requestResponse;
        private final JPanel uiComponent;

        public MyExtensionProvidedHttpRequestEditor() {
            JPanel requestPanel = new JPanel(new BorderLayout());
            requestPanel.add(new JLabel("Request", JLabel.CENTER), BorderLayout.NORTH);
            requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

            JPanel responsePanel = new JPanel(new BorderLayout());
            responsePanel.add(new JLabel("Response", JLabel.CENTER), BorderLayout.NORTH);
            responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

            uiComponent = new JPanel(new BorderLayout());
            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
            splitPane.setDividerLocation(0.5);
            splitPane.setResizeWeight(0.5);
            splitPane.setOneTouchExpandable(true);
            splitPane.setDividerSize(10);
            uiComponent.add(splitPane, BorderLayout.CENTER);
        }

        @Override
        public HttpRequest getRequest() {
            return requestResponse != null ? requestResponse.request() : null;
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            if (requestResponse != null) {
                requestEditor.setContents(requestResponse.request().toByteArray());
                responseEditor.setContents(requestResponse.response() != null ? requestResponse.response().toByteArray() : ByteArray.byteArray("No response".getBytes()));
            }
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse != null;
        }

        @Override
        public String caption() {
            return "Request/Response";
        }

        @Override
        public Component uiComponent() {
            return uiComponent;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    private class MyContextMenuItemsProvider implements ContextMenuItemsProvider {
        private final CustomRequestEditorTab extension;

        public MyContextMenuItemsProvider(CustomRequestEditorTab extension) {
            this.extension = extension;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menuItemList = new ArrayList<>();
            JMenuItem sendToCustomTab = new JMenuItem("Send to WCD Scanner");

            sendToCustomTab.addActionListener(l -> {
                HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ?
                        event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);
                extension.addPacket(requestResponse);
            });
            menuItemList.add(sendToCustomTab);

            return menuItemList;
        }
    }

    /**
     * Shows packet details in the request/response panel.
     */
    private void showPacketDetails(int row) {
        if (detailPane != null && row >= 0 && row < logModel.getRowCount()) {
            String selectedDomain = lastSelectedDomain;
            if (selectedDomain != null) {
                List<PacketInfo> domainSpecificPackets = domainPackets.getOrDefault(selectedDomain, new ArrayList<>());
                if (domainTreeData.containsKey(selectedDomain)) {
                    Set<String> subdomains = domainTreeData.get(selectedDomain);
                    for (String subdomain : subdomains) {
                        domainSpecificPackets.addAll(domainPackets.getOrDefault(subdomain, new ArrayList<>()));
                    }
                }
                List<PacketInfo> filteredPackets = new ArrayList<>();
                for (PacketInfo packetInfo : domainSpecificPackets) {
                    if (applyFilters(packetInfo)) {
                        filteredPackets.add(packetInfo);
                    }
                }
                if (row < filteredPackets.size()) {
                    PacketInfo packetInfo = filteredPackets.get(row);
                    ByteArray requestBytes = extensionData.getByteArray(packetInfo.getStorageKey() + "_request");
                    ByteArray responseBytes = extensionData.getByteArray(packetInfo.getStorageKey() + "_response");
                    if (requestEditor != null && responseEditor != null) {
                        requestEditor.setContents(requestBytes != null ? requestBytes : ByteArray.byteArray("No request".getBytes()));
                        responseEditor.setContents(responseBytes != null ? responseBytes : ByteArray.byteArray("No response".getBytes()));
                    }
                    detailPane.setDividerLocation(0.5);
                    detailPane.setVisible(true);
                    mainPanel.revalidate();
                    mainPanel.repaint();
                }
            }
        }
    }



    private static class DomainNode {
        private final String domain;
        private final boolean isRoot;

        public DomainNode(String domain, boolean isRoot) {
            this.domain = domain;
            this.isRoot = isRoot;
        }

        public String getDomain() {
            return domain;
        }

        public boolean isRoot() {
            return isRoot;
        }

        @Override
        public String toString() {
            return domain;
        }
    }

    
    private class CustomTreeCellRenderer extends DefaultTreeCellRenderer {
        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            Component c = super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            if (c instanceof JLabel) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
                if (node.getUserObject() instanceof DomainNode) {
                    DomainNode nodeData = (DomainNode) node.getUserObject();
                    if (nodeData.isRoot()) {
                        String icon = expanded ? "\u25BC " : "\u25B6 "; // ▼ for expanded, ▶ for collapsed
                        ((JLabel) c).setText(icon + nodeData.getDomain());
                    } else {
                        ((JLabel) c).setText(nodeData.getDomain());
                    }
                    ((JLabel) c).setForeground(new Color(200, 200, 200));
                    if (sel) {
                        ((JLabel) c).setBackground(new Color(60, 130, 200));
                        ((JLabel) c).setOpaque(true);
                    } else {
                        ((JLabel) c).setBackground(tree.getBackground());
                        ((JLabel) c).setOpaque(false);
                    }
                }
            }
            return c;
        }
    }
}
