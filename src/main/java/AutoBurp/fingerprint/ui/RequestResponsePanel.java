package AutoBurp.fingerprint.ui;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.util.Objects;

public class RequestResponsePanel extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IMessageEditorController controller;
    
    
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    
    public RequestResponsePanel(IBurpExtenderCallbacks callbacks, IMessageEditorController controller) {
        this.callbacks = callbacks;
        this.controller = controller;
        
        setLayout(new BorderLayout());
        
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(0.5);
        splitPane.setContinuousLayout(true);
        add(splitPane, BorderLayout.CENTER);
        
        
        requestEditor = callbacks.createMessageEditor(controller, false);
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.add(new JLabel("请求"), BorderLayout.NORTH);
        requestPanel.add(requestEditor.getComponent(), BorderLayout.CENTER);
        splitPane.setLeftComponent(requestPanel);
        
        
        responseEditor = callbacks.createMessageEditor(controller, false);
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.add(new JLabel("响应"), BorderLayout.NORTH);
        responsePanel.add(responseEditor.getComponent(), BorderLayout.CENTER);
        splitPane.setRightComponent(responsePanel);
    }
    
    public void setRequestResponse(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            
            byte[] request = requestResponse.getRequest();
            byte[] response = requestResponse.getResponse();

            
            requestEditor.setMessage(new byte[0], true);
            responseEditor.setMessage(new byte[0], false);
            
            
            if (request != null) {
                requestEditor.setMessage(request, true);
            }

            if (response != null) {
                responseEditor.setMessage(response, false);
            }
        } else {
            clear();
        }
    }
    
    public void clear() {
        requestEditor.setMessage(new byte[0], true);
        responseEditor.setMessage(new byte[0], false);
    }
}