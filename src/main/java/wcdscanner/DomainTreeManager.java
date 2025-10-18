package wcdscanner;

import burp.api.montoya.persistence.PersistedObject;
import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DomainTreeManager {
    private final Map<String, Set<String>> domainTreeData = new HashMap<>();
    private final Map<String, List<PacketInfo>> domainPackets = new HashMap<>();
    private final Map<String, Integer> domainPacketCounters = new HashMap<>();
    private final PersistedObject extensionData;
    private DefaultMutableTreeNode rootNode;
    private DefaultTreeModel domainTreeModel;

    public DomainTreeManager(PersistedObject extensionData) {
        this.extensionData = extensionData;
    }

    public void addDomain(String domain, String fullHost) {
        domainTreeData.computeIfAbsent(domain, k -> new LinkedHashSet<>());
        if (!fullHost.equalsIgnoreCase(domain)) {
            domainTreeData.get(domain).add(fullHost);
        }
    }

    public void addPacket(String host, PacketInfo packetInfo) {
        domainPackets.computeIfAbsent(host, k -> new ArrayList<>()).add(packetInfo);
    }

    public List<PacketInfo> getDomainPackets(String domain) {
        List<PacketInfo> allPackets = domainPackets.getOrDefault(domain, new ArrayList<>());
        if (domainTreeData.containsKey(domain)) {
            Set<String> subdomains = domainTreeData.get(domain);
            for (String subdomain : subdomains) {
                allPackets.addAll(domainPackets.getOrDefault(subdomain, new ArrayList<>()));
            }
        }
        return allPackets;
    }

    public void refreshDomainTree(JTree domainTree) {
        if (rootNode == null) {
            rootNode = new DefaultMutableTreeNode("Domains");
            domainTreeModel = new DefaultTreeModel(rootNode);
            domainTree.setModel(domainTreeModel);
        }
        rootNode.removeAllChildren();
        for (String domain : domainTreeData.keySet()) {
            DefaultMutableTreeNode domainNode = new DefaultMutableTreeNode(new DomainNode(domain, true));
            rootNode.add(domainNode);
        }
        domainTreeModel.reload();
    }

    public void expandDomainTree(JTree domainTree, DefaultTreeModel domainTreeModel, String domain) {
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

    public void deleteSubdomainPackets(String subdomain) {
        List<PacketInfo> packets = domainPackets.remove(subdomain);
        if (packets != null) {
            for (PacketInfo packet : packets) {
                extensionData.deleteByteArray(packet.getStorageKey() + "_request");
                extensionData.deleteByteArray(packet.getStorageKey() + "_response");
            }
        }
        String baseDomain = extractBaseDomain(subdomain);
        Set<String> subdomains = domainTreeData.get(baseDomain);
        if (subdomains != null) {
            subdomains.remove(subdomain);
            if (subdomains.isEmpty()) {
                domainTreeData.remove(baseDomain);
            }
        }
    }

    public String extractBaseDomain(String host) {
        String[] parts = host.split("\\.");
        if (parts.length > 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }
}
