package wcdscanner;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuProvider implements ContextMenuItemsProvider {
    private final WCDScannerExtension extension;

    public ContextMenuProvider(WCDScannerExtension extension) {
        this.extension = extension;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();
        JMenuItem sendToCustomTab = new JMenuItem("Send to WCD Scanner");

        sendToCustomTab.addActionListener(l -> {
            burp.api.montoya.http.message.HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ?
                    event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);
            extension.addPacket(requestResponse);
        });
        menuItemList.add(sendToCustomTab);

        return menuItemList;
    }
}
