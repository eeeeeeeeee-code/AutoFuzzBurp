package AutoBurp.bypass;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.RawEditor;
import AutoBurp.bypass.beens.Browsers;
import AutoBurp.bypass.beens.DomainSettings;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.List;

public class DomainSettingsPanel extends JPanel {
    private final MontoyaApi montoyaApi;
    private final JTable settingsTable;
    private final SettingsTableModel tableModel;
    private final RawEditor detailsEditor;
    private Timer autoRefreshTimer; 
    
    
    private static final Color PRIMARY_COLOR = new Color(120, 103, 180);
    private static final Color SECONDARY_COLOR = new Color(52, 128, 83);
    private static final Color BACKGROUND_COLOR = new Color(250, 250, 250);
    private static final Color CARD_BACKGROUND = new Color(255, 255, 255);
    private static final Color TEXT_COLOR = new Color(60, 64, 67);
    private static final Color BORDER_COLOR = new Color(218, 220, 224);
    
    
    private static final Font TITLE_FONT = new Font("Dialog", Font.BOLD, 14);
    private static final Font NORMAL_FONT = new Font("Dialog", Font.BOLD, 13);
    private static final Font BUTTON_FONT = new Font("Dialog", Font.BOLD, 13);

    public DomainSettingsPanel(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.setLayout(new BorderLayout(0, 10));
        this.setBackground(BACKGROUND_COLOR);
        this.setBorder(new EmptyBorder(15, 15, 15, 15));

        
        tableModel = new SettingsTableModel();
        settingsTable = createStylizedTable(tableModel);
        
        
        detailsEditor = montoyaApi.userInterface().createRawEditor();
        detailsEditor.setEditable(false);
        
        
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBackground(BACKGROUND_COLOR);
        titlePanel.setBorder(new EmptyBorder(0, 0, 10, 0));
        
        JLabel titleLabel = new JLabel("TLS WAF");
        titleLabel.setFont(TITLE_FONT);
        titleLabel.setForeground(PRIMARY_COLOR);
        titlePanel.add(titleLabel, BorderLayout.WEST);

        
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBackground(BACKGROUND_COLOR);
        
        
        JButton addButton = createStylizedButton("添加域名", PRIMARY_COLOR);
        addButton.addActionListener(e -> showAddDomainDialog());
        
        
        JButton editButton = createStylizedButton("修改设置", SECONDARY_COLOR);
        editButton.addActionListener(e -> {
            int selectedRow = settingsTable.getSelectedRow();
            if (selectedRow >= 0) {
                DomainSettings settings = tableModel.getSettingAt(selectedRow);
                showEditDomainDialog(settings);
            } else {
                showStylizedMessage("请先选择一个域名", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        
        JButton deleteButton = createStylizedButton("删除设置", new Color(234, 67, 53));
        deleteButton.addActionListener(e -> {
            int selectedRow = settingsTable.getSelectedRow();
            if (selectedRow >= 0) {
                DomainSettings settings = tableModel.getSettingAt(selectedRow);
                int result = showConfirmDialog(
                        "确定要删除域名 " + settings.getDomain() + " 的设置吗？",
                        "确认删除"
                );
                if (result == JOptionPane.YES_OPTION) {
                    DomainSettingsManager.removeDomainSettings(settings.getDomain());
                    Utilities.loadTLSSettings();
                    refreshTable();
                    showStylizedMessage("已删除域名设置并恢复默认 TLS 配置", "提示", JOptionPane.INFORMATION_MESSAGE);
                }
            } else {
                showStylizedMessage("请先选择一个域名", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        titlePanel.add(buttonPanel, BorderLayout.EAST);
        
        
        JPanel tableCard = createCardPanel();
        tableCard.setLayout(new BorderLayout());
        JScrollPane tableScrollPane = new JScrollPane(settingsTable);
        tableScrollPane.setBorder(null);
        tableScrollPane.getViewport().setBackground(CARD_BACKGROUND);
        tableCard.add(tableScrollPane, BorderLayout.CENTER);
        
        
        JPanel detailsCard = createCardPanel();
        detailsCard.setLayout(new BorderLayout());
        JLabel detailsLabel = new JLabel("详细信息");
        detailsLabel.setFont(TITLE_FONT);
        detailsLabel.setForeground(TEXT_COLOR);
        detailsLabel.setBorder(new EmptyBorder(10, 10, 10, 10));
        detailsCard.add(detailsLabel, BorderLayout.NORTH);
        
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.setBackground(CARD_BACKGROUND);
        editorPanel.setBorder(new EmptyBorder(0, 10, 10, 10));
        editorPanel.add(detailsEditor.uiComponent(), BorderLayout.CENTER);
        detailsCard.add(editorPanel, BorderLayout.CENTER);
        
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tableCard);
        splitPane.setBottomComponent(detailsCard);
        splitPane.setDividerLocation(300);
        splitPane.setDividerSize(8);
        splitPane.setBorder(null);
        
        this.add(titlePanel, BorderLayout.NORTH);
        this.add(splitPane, BorderLayout.CENTER);

        refreshTable();
        
        autoRefreshTimer = new Timer(5000, e -> refreshTable());
        autoRefreshTimer.start();
    }
    
    
    private JPanel createCardPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(CARD_BACKGROUND);
        panel.setBorder(new CompoundBorder(
                new LineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(5, 5, 5, 5)
        ));
        return panel;
    }
    
    
    private JButton createStylizedButton(String text, Color color) {
        JButton button = new JButton(text);
        button.setFont(BUTTON_FONT);
        button.setForeground(Color.WHITE);
        button.setBackground(color);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setPreferredSize(new Dimension(100, 30));
        
        
        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                button.setBackground(darken(color, 0.1f));
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                button.setBackground(color);
            }
        });
        
        return button;
    }
    
    
    private JTable createStylizedTable(SettingsTableModel model) {
        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(30);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setFont(NORMAL_FONT);
        table.setForeground(TEXT_COLOR);
        table.setSelectionBackground(new Color(232, 240, 254));
        table.setSelectionForeground(TEXT_COLOR);
        
        
        JTableHeader header = table.getTableHeader();
        header.setFont(BUTTON_FONT);
        header.setBackground(new Color(240, 240, 240));
        header.setForeground(TEXT_COLOR);
        header.setBorder(new LineBorder(BORDER_COLOR, 1));
        
        
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    c.setBackground(row % 2 == 0 ? CARD_BACKGROUND : new Color(248, 249, 250));
                }
                setBorder(new EmptyBorder(0, 10, 0, 10));
                return c;
            }
        };
        renderer.setHorizontalAlignment(SwingConstants.LEFT);
        
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }
        
        
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateDetailsPanel();
            }
        });
        
        return table;
    }
    
    
    private int showConfirmDialog(String message, String title) {
        UIManager.put("OptionPane.background", CARD_BACKGROUND);
        UIManager.put("Panel.background", CARD_BACKGROUND);
        UIManager.put("OptionPane.messageForeground", TEXT_COLOR);
        UIManager.put("OptionPane.messageFont", NORMAL_FONT);
        UIManager.put("OptionPane.buttonFont", BUTTON_FONT);
        
        return JOptionPane.showConfirmDialog(
                this,
                message,
                title,
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
        );
    }
    
    
    private void showStylizedMessage(String message, String title, int messageType) {
        UIManager.put("OptionPane.background", CARD_BACKGROUND);
        UIManager.put("Panel.background", CARD_BACKGROUND);
        UIManager.put("OptionPane.messageForeground", TEXT_COLOR);
        UIManager.put("OptionPane.messageFont", NORMAL_FONT);
        UIManager.put("OptionPane.buttonFont", BUTTON_FONT);
        
        JOptionPane.showMessageDialog(this, message, title, messageType);
    }
    
    
    private Color darken(Color color, float fraction) {
        int red = Math.max(0, Math.round(color.getRed() * (1 - fraction)));
        int green = Math.max(0, Math.round(color.getGreen() * (1 - fraction)));
        int blue = Math.max(0, Math.round(color.getBlue() * (1 - fraction)));
        return new Color(red, green, blue);
    }
    
    
    @Override
    public void removeNotify() {
        super.removeNotify();
        if (autoRefreshTimer != null) {
            autoRefreshTimer.stop();
            autoRefreshTimer = null;
        }
    }

    private void refreshTable() {
        
        String selectedDomain = null;
        int selectedRow = settingsTable.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < tableModel.getRowCount()) {
            selectedDomain = (String) tableModel.getValueAt(selectedRow, 0);
        }
        
        
        tableModel.setData(DomainSettingsManager.getAllDomainSettings());
        tableModel.fireTableDataChanged();
        
        
        if (selectedDomain != null) {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                if (selectedDomain.equals(tableModel.getValueAt(i, 0))) {
                    settingsTable.setRowSelectionInterval(i, i);
                    
                    Rectangle rect = settingsTable.getCellRect(i, 0, true);
                    settingsTable.scrollRectToVisible(rect);
                    break;
                }
            }
        }
    }

    private void updateDetailsPanel() {
        int selectedRow = settingsTable.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < tableModel.getRowCount()) {
            DomainSettings settings = tableModel.getSettingAt(selectedRow);
            StringBuilder details = new StringBuilder();
            details.append("域名: ").append(settings.getDomain()).append("\n\n");
            details.append("浏览器: ").append(settings.getBrowser()).append("\n\n");
            details.append("协议: ").append(Arrays.toString(settings.getProtocols())).append("\n\n");
            details.append("密码套件: ").append(Arrays.toString(settings.getCiphers())).append("\n\n");
            details.append("HTTP降级: ").append(settings.isHttpDowngrade() ? "是" : "否").append("\n\n");
            details.append("记录时间: ").append(settings.getTimestamp()).append("\n");
            
            detailsEditor.setContents(ByteArray.byteArray(details.toString().getBytes()));
        } else {
            detailsEditor.setContents(ByteArray.byteArray("请选择一个域名查看详细信息".getBytes()));
        }
    }
    
    private void showAddDomainDialog() {
        
        JTextField domainField = new JTextField(20);
        styleTextField(domainField);
        
        JComboBox<Browsers> browserCombo = new JComboBox<>(Browsers.values());
        styleComboBox(browserCombo);
        
        JCheckBox httpDowngradeCheckbox = new JCheckBox("启用 HTTP 降级");
        styleCheckBox(httpDowngradeCheckbox);
        
        JPanel panel = new JPanel(new GridLayout(0, 1, 0, 10));
        panel.setBackground(CARD_BACKGROUND);
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));
        
        JLabel domainLabel = new JLabel("域名:");
        domainLabel.setFont(NORMAL_FONT);
        domainLabel.setForeground(TEXT_COLOR);
        
        JLabel browserLabel = new JLabel("浏览器:");
        browserLabel.setFont(NORMAL_FONT);
        browserLabel.setForeground(TEXT_COLOR);
        
        panel.add(domainLabel);
        panel.add(domainField);
        panel.add(browserLabel);
        panel.add(browserCombo);
        panel.add(httpDowngradeCheckbox);
        
        
        UIManager.put("OptionPane.background", CARD_BACKGROUND);
        UIManager.put("Panel.background", CARD_BACKGROUND);
        UIManager.put("OptionPane.messageForeground", TEXT_COLOR);
        
        int result = JOptionPane.showConfirmDialog(
                this, panel, "添加域名设置", 
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        
        if (result == JOptionPane.OK_OPTION) {
            String domain = domainField.getText().trim();
            if (domain.isEmpty()) {
                showStylizedMessage("域名不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            Browsers browser = (Browsers) browserCombo.getSelectedItem();
            boolean httpDowngrade = httpDowngradeCheckbox.isSelected();
            
            DomainSettingsManager.addDomainSettings(
                    domain,
                    browser,
                    Constants.BROWSERS_PROTOCOLS.get(browser.name),
                    Constants.BROWSERS_CIPHERS.get(browser.name),
                    httpDowngrade
            );
            
            refreshTable();
            showStylizedMessage("已添加域名 " + domain + " 的设置", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void showEditDomainDialog(DomainSettings settings) {
        try {
            
            JTextField domainField = new JTextField(settings.getDomain(), 20);
            domainField.setEditable(false);
            styleTextField(domainField);
            
            
            Browsers selectedBrowser = null;
            try {
                selectedBrowser = Browsers.valueOf(settings.getBrowser());
            } catch (IllegalArgumentException e) {
                selectedBrowser = Browsers.FIREFOX; 
                Utilities.error("无法识别的浏览器类型: " + settings.getBrowser() + ", 使用默认值 FIREFOX");
            }
            
            JComboBox<Browsers> browserCombo = new JComboBox<>(Browsers.values());
            browserCombo.setSelectedItem(selectedBrowser);
            styleComboBox(browserCombo);
            
            JCheckBox httpDowngradeCheckbox = new JCheckBox("启用 HTTP 降级", settings.isHttpDowngrade());
            styleCheckBox(httpDowngradeCheckbox);
            
            JPanel panel = new JPanel(new GridLayout(0, 1, 0, 10));
            panel.setBackground(CARD_BACKGROUND);
            panel.setBorder(new EmptyBorder(15, 15, 15, 15));
            
            JLabel domainLabel = new JLabel("域名:");
            domainLabel.setFont(NORMAL_FONT);
            domainLabel.setForeground(TEXT_COLOR);
            
            JLabel browserLabel = new JLabel("浏览器:");
            browserLabel.setFont(NORMAL_FONT);
            browserLabel.setForeground(TEXT_COLOR);
            
            panel.add(domainLabel);
            panel.add(domainField);
            panel.add(browserLabel);
            panel.add(browserCombo);
            panel.add(httpDowngradeCheckbox);
            
            
            UIManager.put("OptionPane.background", CARD_BACKGROUND);
            UIManager.put("Panel.background", CARD_BACKGROUND);
            UIManager.put("OptionPane.messageForeground", TEXT_COLOR);
            
            int result = JOptionPane.showConfirmDialog(
                    this, panel, "修改域名设置", 
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            
            if (result == JOptionPane.OK_OPTION) {
                Browsers browser = (Browsers) browserCombo.getSelectedItem();
                boolean httpDowngrade = httpDowngradeCheckbox.isSelected();
                
                DomainSettingsManager.updateDomainSettings(
                        settings.getDomain(),
                        browser,
                        Constants.BROWSERS_PROTOCOLS.get(browser.name),
                        Constants.BROWSERS_CIPHERS.get(browser.name),
                        httpDowngrade
                );
                
                refreshTable();
                showStylizedMessage("已更新域名 " + settings.getDomain() + " 的设置", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            Utilities.error("修改域名设置时出错: " + e.getMessage());
            showStylizedMessage("修改设置失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    
    private void styleTextField(JTextField textField) {
        textField.setFont(NORMAL_FONT);
        textField.setForeground(TEXT_COLOR);
        textField.setBorder(new CompoundBorder(
                new LineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(5, 8, 5, 8)
        ));
    }
    
    
    private void styleComboBox(JComboBox<?> comboBox) {
        comboBox.setFont(NORMAL_FONT);
        comboBox.setForeground(TEXT_COLOR);
        comboBox.setBackground(Color.WHITE);
        comboBox.setBorder(new LineBorder(BORDER_COLOR, 1, true));
    }
    
    
    private void styleCheckBox(JCheckBox checkBox) {
        checkBox.setFont(NORMAL_FONT);
        checkBox.setForeground(TEXT_COLOR);
        checkBox.setBackground(CARD_BACKGROUND);
    }

    private static class SettingsTableModel extends AbstractTableModel {
        private final String[] columnNames = {"域名", "浏览器", "HTTP降级", "记录时间"};
        private List<DomainSettings> data;

        public void setData(List<DomainSettings> data) {
            this.data = data;
        }

        public DomainSettings getSettingAt(int row) {
            return data.get(row);
        }

        @Override
        public int getRowCount() {
            return data == null ? 0 : data.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DomainSettings settings = data.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> settings.getDomain();
                case 1 -> settings.getBrowser();
                case 2 -> settings.isHttpDowngrade() ? "是" : "否";
                case 3 -> settings.getTimestamp();
                default -> null;
            };
        }
    }
}