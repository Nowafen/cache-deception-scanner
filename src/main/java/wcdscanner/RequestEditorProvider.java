package wcdscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import javax.swing.*;
import java.awt.*;

public class RequestEditorProvider implements HttpRequestEditorProvider {
    private final MontoyaApi api;

    public RequestEditorProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new MyExtensionProvidedHttpRequestEditor(api);
    }

    private static class MyExtensionProvidedHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final HttpRequestEditor requestEditor;
        private final HttpResponseEditor responseEditor;
        private HttpRequestResponse requestResponse;
        private final JPanel uiComponent;
        private final MontoyaApi api; // Added api field

        public MyExtensionProvidedHttpRequestEditor(MontoyaApi api) {
            this.api = api; // Store api instance
            this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

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
                requestEditor.setRequest(requestResponse.request());
                responseEditor.setResponse(requestResponse.response() != null ? requestResponse.response() : HttpResponse.httpResponse(ByteArray.byteArray("No response".getBytes())));
            } else {
                requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray("No request".getBytes())));
                responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray("No response".getBytes())));
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
        public burp.api.montoya.ui.Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }
}
