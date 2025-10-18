package wcdscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class WCDScannerExtension implements BurpExtension {
    private ExecutorService executorService;
    private MontoyaApi api;
    private PersistedObject extensionData;
    private UIComponents uiComponents;
    private PacketProcessor packetProcessor;
    private DomainTreeManager domainTreeManager;
    private FilterManager filterManager;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.executorService = Executors.newFixedThreadPool(5);
        this.extensionData = api.persistence().extensionData();
        api.extension().setName("WCD Scanner");

        // Initialize components
        this.domainTreeManager = new DomainTreeManager(extensionData);
        this.filterManager = new FilterManager(extensionData, domainTreeManager);
        this.uiComponents = new UIComponents(api, domainTreeManager, filterManager, this::updateLogTableForDomain);
        this.packetProcessor = new PacketProcessor(api, executorService, extensionData, domainTreeManager, filterManager, uiComponents);

        // Register handlers and UI
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

        api.userInterface().registerHttpRequestEditorProvider(new RequestEditorProvider(api));
        api.userInterface().registerSuiteTab("WCD Scanner", uiComponents.getMainPanel());
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuProvider(this));
    }

    public void addPacket(burp.api.montoya.http.message.HttpRequestResponse requestResponse) {
        packetProcessor.addPacket(requestResponse);
    }

    private void updateLogTableForDomain(String domain) {
        uiComponents.updateLogTableForDomain(domain);
    }
}
