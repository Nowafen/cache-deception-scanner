package wcdscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class UIComponents {
    private final MontoyaApi api;
    private final DomainTreeManager domainTreeManager;
    private final FilterManager filterManager;
    private final Consumer<String> updateLogTableCallback;
    private JPanel mainPanel;
    private JTree domainTree;
    private DefaultTreeModel domainTreeModel;
    private DefaultMutableTreeNode rootNode;
    private JTable logTable;
    private DefaultTableModel logModel;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JSplitPane detailPane;
    private JTabbedPane domainTabbedPane;
    private JPanel domainPanel;
    private String lastSelectedDomain = null;
    private TableRowSorter<DefaultTableModel> sorter;
    private final Map<String, Integer> domainPacketCounters = new HashMap<>();

    public UIComponents(MontoyaApi api, DomainTreeManager domainTreeManager, FilterManager filterManager, Consumer<String> updateLogTableCallback) {
        this.api = api;
        this.domainTreeManager = domainTreeManager;
        this.filterManager = filterManager;
        this.updateLogTableCallback = updateLogTableCallback;
        setupUI();
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public JTree getDomainTree() {
        return domainTree;
    }

    public String getLastSelectedDomain() {
        return lastSelectedDomain;
    }

    public DefaultTableModel getLogModel() {
        return logModel;
    }

    public JTable getLogTable() {
        return logTable;
    }

    public void updateLogTable(PacketInfo packetInfo) {
        if (filterManager.applyFilters(packetInfo) && lastSelectedDomain != null &&
                isSubdomainOrSame(lastSelectedDomain, packetInfo.getUrl())) {
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

    public void updateLogTableForDomain(String domain) {
        logModel.setRowCount(0);
        if (domain == null) {
            logTable.setVisible(false);
            return;
        }
        logTable.setVisible(true);
        domainPacketCounters.put(domain, 1);
        List<PacketInfo> allPackets = domainTreeManager.getDomainPackets(domain);
        for (PacketInfo packetInfo : allPackets) {
            if (filterManager.applyFilters(packetInfo)) {
                updateLogTable(packetInfo);
            }
        }
    }

    private boolean isSubdomainOrSame(String domain, String url) {
        String host = url.contains("://") ? url.split("/")[2].split(":")[0] : "N/A";
        if (host.equals(domain)) return true;
        String baseDomain = domainTreeManager.extractBaseDomain(host);
        return baseDomain.equals(domain);
    }

    private void setupUI() {
        mainPanel = new JPanel(new BorderLayout());
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
                                domainTreeManager.expandDomainTree(domainTree, domainTreeModel, selectedDomain);
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

        JPanel settingsFilterPanel = createSettingsFilterPanel();
        JPanel sendSettingsPanel = createSendSettingsPanel();

        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
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
                showPacketDetails(row); // Fixed: Changed updatePacketDetails to showPacketDetails
            }
        });
    }

    private JPanel createSettingsFilterPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        panel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        panel.setMaximumSize(new Dimension(1500, 35));
        panel.setPreferredSize(new Dimension(1500, 35));

        JLabel iconLabel = new JLabel("\u2699");
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
                filterManager.showSettingsDialog(mainPanel, lastSelectedDomain, UIComponents.this::updateLogTableForDomain);
            }
        });

        return panel;
    }

    private JPanel createSendSettingsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        panel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        panel.setMaximumSize(new Dimension(200, 35));
        panel.setPreferredSize(new Dimension(200, 35));

        JLabel iconLabel = new JLabel("\u27A4");
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
                filterManager.showSendSettingsDialog(mainPanel);
            }
        });

        return panel;
    }

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
                domainTreeManager.deleteSubdomainPackets(selectedDomain);
                domainTabbedPane.remove(actionsPanel);
                domainTabbedPane.setSelectedIndex(0);
                lastSelectedDomain = null;
                updateLogTableForDomain(null);
            }
        });
        buttonPanel.add(deleteButton);
        actionsPanel.add(buttonPanel, BorderLayout.CENTER);

        domainTabbedPane.addTab("Domain Actions", actionsPanel);
        domainTabbedPane.setSelectedIndex(domainTabbedPane.getTabCount() - 1);
    }

    private void showPacketDetails(int row) {
        if (detailPane != null && row >= 0 && row < logModel.getRowCount()) {
            String selectedDomain = lastSelectedDomain;
            if (selectedDomain != null) {
                List<PacketInfo> domainSpecificPackets = domainTreeManager.getDomainPackets(selectedDomain);
                List<PacketInfo> filteredPackets = new ArrayList<>();
                for (PacketInfo packetInfo : domainSpecificPackets) {
                    if (filterManager.applyFilters(packetInfo)) {
                        filteredPackets.add(packetInfo);
                    }
                }
                if (row < filteredPackets.size()) {
                    PacketInfo packetInfo = filteredPackets.get(row);
                    
                    ByteArray requestBytes = filterManager.getExtensionData().getByteArray(packetInfo.getStorageKey() + "_request");
                    ByteArray responseBytes = filterManager.getExtensionData().getByteArray(packetInfo.getStorageKey() + "_response");
                    
                    ByteArray emptyBytes = ByteArray.byteArray("No Data Available".getBytes());
                    if (requestBytes == null) requestBytes = emptyBytes;
                    if (responseBytes == null) responseBytes = emptyBytes;

                    // Fixed: Convert ByteArray to HttpRequest and HttpResponse
                    HttpRequest request = HttpRequest.httpRequest(requestBytes);
                    HttpResponse response = HttpResponse.httpResponse(responseBytes);

                    if (requestEditor != null && responseEditor != null) {
                        requestEditor.setRequest(request);
                        responseEditor.setResponse(response);
                    }
                    
                    detailPane.setDividerLocation(0.5);
                    detailPane.setVisible(true);
                    mainPanel.revalidate();
                    mainPanel.repaint();
                }
            }
        }
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

    private class VulnerabilityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value != null && value.toString().contains("vulnerable packet")) {
                c.setForeground(Color.GREEN);  // Green for vulnerable
            } else {
                c.setForeground(table.getForeground());  // Default color for others
            }
            return c;
        }
    }
}
