package AutoBurp.fingerprint.ui;

import AutoBurp.bypass.DomainSettingsPanel;
import AutoBurp.fingerprint.FingerPrintScanner;
import AutoBurp.fingerprint.model.FingerPrintRule;
import AutoBurp.fingerprint.model.TableLogModel;
import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public class FingerPrintTab extends JPanel implements IMessageEditorController, ITab {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JSplitPane splitPane;
    private IHttpRequestResponse currentlyDisplayedItem;
    private final List<TableLogModel> logEntries = new CopyOnWriteArrayList<>();
    private final Set<String> uniqueTypes = Collections.synchronizedSet(new HashSet<>());
    
    
    private ControlPanel controlPanel;
    private TagsPanel tagsPanel;
    private LogTablePanel logTablePanel;
    private RequestResponsePanel requestResponsePanel;
    
    
    private FingerPrintRulePanel rulePanel;
    private JTabbedPane tabbedPane;
    
    
    private DomainSettingsPanel domainSettingsPanel;
    
    
    private static final Color SECONDARY_COLOR = new Color(245, 245, 245);
    private FingerPrintScanner scanner;

    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(SECONDARY_COLOR);
        panel.setBorder(new EmptyBorder(0, 0, 5, 0));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        
        
        gbc.gridy = 0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(0, 0, 5, 0);
        controlPanel = new ControlPanel(callbacks);
        controlPanel.setOnRefreshListener(this::refreshTable);
        controlPanel.setOnClearListener(this::clearTable);
        
        controlPanel.setOnScanStateChangedListener(this::onScanStateChanged);
        
        
        controlPanel.setPreferredSize(new Dimension(0, 60));
        panel.add(controlPanel, gbc);
        
        
        gbc.gridy = 1;
        gbc.insets = new Insets(0, 0, 5, 0);
        tagsPanel = new TagsPanel();
        tagsPanel.setOnTagSelectedListener(this::filterTableByType);
        
        tagsPanel.setPreferredSize(new Dimension(0, 50));
        tagsPanel.setMinimumSize(new Dimension(0, 50));
        panel.add(tagsPanel, gbc);
        
        
        gbc.gridy = 2;
        gbc.weighty = 1.0; 
        gbc.insets = new Insets(0, 0, 0, 0); 
        logTablePanel = new LogTablePanel(callbacks, helpers, logEntries, uniqueTypes);
        logTablePanel.setOnRowSelectedListener(this::onLogEntrySelected);
        logTablePanel.setOnTypeFilterChangedListener(tagsPanel::selectTag);
        
        logTablePanel.setBorder(null);
        panel.add(logTablePanel, gbc);
        
        return panel;
    }
    
    
    public FingerPrintTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        
        
        setLayout(new BorderLayout());
        setBackground(SECONDARY_COLOR);
        setBorder(new EmptyBorder(10, 10, 10, 10));
        
        
        tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(Color.WHITE);
        
        
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setBorder(null);
        splitPane.setBackground(SECONDARY_COLOR);
        splitPane.setDividerSize(5);
        
        splitPane.setContinuousLayout(true);
        
        
        JPanel topPanel = createTopPanel();
        splitPane.setLeftComponent(topPanel);
        
        
        requestResponsePanel = new RequestResponsePanel(callbacks, this);
        splitPane.setRightComponent(requestResponsePanel);
        
        
        splitPane.setResizeWeight(0.75); 
        
        
        addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int height = getHeight();
                    splitPane.setDividerLocation((int)(height * 0.70));
                });
            }
        });
        
        
        tabbedPane.addTab("指纹识别", splitPane);

        
        add(tabbedPane, BorderLayout.CENTER);

    }
    
    
    public void setRulePanel(List<FingerPrintRule> rules) {
        
        rulePanel = new FingerPrintRulePanel(callbacks, helpers, rules);

        
        rulePanel.setOnRulesUpdatedListener(this::onRulesUpdated);

        
        tabbedPane.addTab("指纹管理", rulePanel);
        
        

    }

    private void onLogEntrySelected(TableLogModel entry) {
        
        if (entry != null) {
            try {
                
                IHttpRequestResponse requestResponse = entry.getHttpRequestResponse();
                
                if (requestResponse != null) {
                    currentlyDisplayedItem = requestResponse;
                    requestResponsePanel.setRequestResponse(currentlyDisplayedItem);
                    



                } else {


                    currentlyDisplayedItem = null;
                    requestResponsePanel.clear();
                }
            } catch (Exception e) {
                callbacks.printError("[!] 加载请求/响应数据时出错: " + e.getMessage());
                e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
                currentlyDisplayedItem = null;
                requestResponsePanel.clear();
            }
        } else {
            currentlyDisplayedItem = null;
            requestResponsePanel.clear();
        }
    }
    
    private void filterTableByType(String type) {
        logTablePanel.filterTable(type, null);
    }
    
    private void refreshTable() {
        logTablePanel.filterTable(null, null);
    }
    
    public void addLogEntry(TableLogModel entry) {
        if (entry != null) {
            
            synchronized (logEntries) {
                
                entry.setId(logEntries.size() + 1);
                
                
                if (entry.getHttpRequestResponse() == null) {
                    callbacks.printError("[!] 警告: 添加的日志条目没有关联的请求/响应对象: " + entry.getUrl());
                }
                
                logEntries.add(entry);
                
                
                final int entriesSize = logEntries.size();
                
                
                final long successCount = logEntries.stream()
                        .filter(e -> e.getStatus() >= 200 && e.getStatus() < 400)
                        .count();
                
                
                boolean needUpdateTags = false;
                if (entry.getType() != null && !entry.getType().isEmpty()) {
                    synchronized (uniqueTypes) {
                        needUpdateTags = uniqueTypes.add(entry.getType());
                    }
                }
                
                
                final boolean finalNeedUpdateTags = needUpdateTags;
                SwingUtilities.invokeLater(() -> {
                    controlPanel.setRequestCount(entriesSize);
                    controlPanel.setSuccessCount((int) successCount);
                    
                    
                    if (finalNeedUpdateTags && entry.getType() != null && !entry.getType().isEmpty()) {
                        tagsPanel.addTag(entry.getType());
                    }
                    
                    
                    logTablePanel.safeUpdateTable();
                });
            }
        }
    }

    
    private void clearTable() {
        
        synchronized (logEntries) {
            logEntries.clear();
            
            synchronized (uniqueTypes) {
                uniqueTypes.clear();
            }
            
            
            SwingUtilities.invokeLater(() -> {
                logTablePanel.clearTable();
                
                logTablePanel.safeUpdateTable();
                tagsPanel.clearTags();
                requestResponsePanel.clear();
                controlPanel.setRequestCount(0);
                controlPanel.setSuccessCount(0);
            });
        }
    }

    public boolean isScanEnabled() {
        return controlPanel.isScanEnabled();
    }

    
    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getHttpService();
    }
    
    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getRequest();
    }
    
    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getResponse();
    }
    
    
    @Override
    public String getTabCaption() {
        return "Auto fuzz";
    }
    
    @Override
    public Component getUiComponent() {
        return this;
    }
    
    
    public void updateRequestCount(int count) {
        controlPanel.setRequestCount(count);
    }
    
    public void updateSuccessCount(int count) {
        controlPanel.setSuccessCount(count);
    }

    /**
     * 处理扫描状态变化的方法
     */
    
    
    public void setScanner(FingerPrintScanner scanner) {
        this.scanner = scanner;
    }
    
    
    private void onScanStateChanged() {
        boolean isEnabled = controlPanel.isScanEnabled();
        
        
        if (scanner != null) {
            scanner.setAcceptingNewTasks(isEnabled);
        }
        
        
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(this, 
                "指纹识别扫描已" + (isEnabled ? "开启" : "停止") + "，" + 
                (isEnabled ? "新的请求将被扫描。" : "新的请求将不再被扫描。"), 
                "扫描状态变更", 
                JOptionPane.INFORMATION_MESSAGE);
        });
        
        

    }

    
    private void onRulesUpdated(List<FingerPrintRule> updatedRules) {
        
        if (scanner != null) {
            scanner.updateRules(updatedRules);

            
            
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(this, 
                    "指纹规则已成功更新，共 " + updatedRules.size() + " 条规则", 
                    "规则更新成功", 
                    JOptionPane.INFORMATION_MESSAGE);
            });
        } else {
            callbacks.printError("[!] 无法更新指纹规则：扫描器未初始化");
        }
    }
}