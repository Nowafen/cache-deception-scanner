package wcdscanner;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;

public class CustomTreeCellRenderer extends DefaultTreeCellRenderer {
    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        Component c = super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
        if (c instanceof JLabel) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
            if (node.getUserObject() instanceof DomainNode) {
                DomainNode nodeData = (DomainNode) node.getUserObject();
                if (nodeData.isRoot()) {
                    String icon = expanded ? "\u25BC " : "\u25B6 ";
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
