package AutoBurp.fingerprint.ui;

import AutoBurp.fingerprint.model.FingerPrintRule;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;

public class FingerPrintRulePanel extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private List<FingerPrintRule> fingerprintRules;
    private DefaultTableModel tableModel;
    private JTable rulesTable;
    private TableRowSorter<DefaultTableModel> sorter;
    private JTextField searchField;
    private JComboBox<String> typeFilterComboBox;
    private JComboBox<String> importantFilterComboBox;
    private Consumer<List<FingerPrintRule>> onRulesUpdatedListener;
    
    
    private static final Color PRIMARY_COLOR = new Color(60, 141, 188);
    private static final Color SECONDARY_COLOR = new Color(245, 245, 245);
    private static final Color TEXT_COLOR = new Color(51, 51, 51);
    private static final Color BORDER_COLOR = new Color(221, 221, 221);
    
    public FingerPrintRulePanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, List<FingerPrintRule> rules) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.fingerprintRules = new ArrayList<>(rules);
        
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));
        setBackground(Color.WHITE);
        
        
        JPanel controlPanel = createControlPanel();
        add(controlPanel, BorderLayout.NORTH);
        
        
        JPanel tablePanel = createTablePanel();
        add(tablePanel, BorderLayout.CENTER);
        
        
        loadRulesToTable();
    }
    
    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(SECONDARY_COLOR);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR),
                new EmptyBorder(10, 10, 10, 10)
        ));
        
        
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        searchPanel.setBackground(SECONDARY_COLOR);
        
        
        JLabel searchLabel = new JLabel("搜索:");
        searchLabel.setForeground(TEXT_COLOR);
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filterTable();
            }
            
            @Override
            public void removeUpdate(DocumentEvent e) {
                filterTable();
            }
            
            @Override
            public void changedUpdate(DocumentEvent e) {
                filterTable();
            }
        });
        
        
        JLabel typeLabel = new JLabel("类型:");
        typeLabel.setForeground(TEXT_COLOR);
        typeFilterComboBox = new JComboBox<>();
        typeFilterComboBox.addItem("全部");
        typeFilterComboBox.addActionListener(e -> filterTable());
        
        
        JLabel importantLabel = new JLabel("重要性:");
        importantLabel.setForeground(TEXT_COLOR);
        importantFilterComboBox = new JComboBox<>();
        importantFilterComboBox.addItem("全部");
        importantFilterComboBox.addItem("重要");
        importantFilterComboBox.addItem("普通");
        importantFilterComboBox.addActionListener(e -> filterTable());
        
        searchPanel.add(searchLabel);
        searchPanel.add(searchField);
        searchPanel.add(typeLabel);
        searchPanel.add(typeFilterComboBox);
        searchPanel.add(importantLabel);
        searchPanel.add(importantFilterComboBox);
        
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBackground(SECONDARY_COLOR);
        
        JButton addButton = new JButton("添加规则");
        addButton.setBackground(PRIMARY_COLOR);
        addButton.setForeground(Color.WHITE);
        addButton.addActionListener(e -> showRuleDialog(null));
        
        JButton importButton = new JButton("导入规则");
        importButton.setBackground(PRIMARY_COLOR);
        importButton.setForeground(Color.WHITE);
        importButton.addActionListener(e -> importRulesFromFile());

        
        JButton saveButton = new JButton("保存所有指纹");
        saveButton.setBackground(PRIMARY_COLOR);
        saveButton.setForeground(Color.WHITE);
        saveButton.addActionListener(e -> saveRulesToFile());
        
        buttonPanel.add(addButton);
        buttonPanel.add(importButton);
        buttonPanel.add(saveButton);
        
        
        panel.add(searchPanel, BorderLayout.WEST);
        panel.add(buttonPanel, BorderLayout.EAST);
        
        return panel;
    }
    
    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);
        
        
        String[] columnNames = {"ID", "CMS名称", "类型", "方法", "位置", "关键词", "重要性"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        
        rulesTable = new JTable(tableModel);
        rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        rulesTable.setRowHeight(25);
        rulesTable.getTableHeader().setReorderingAllowed(false);
        rulesTable.getTableHeader().setBackground(SECONDARY_COLOR);
        
        
        sorter = new TableRowSorter<>(tableModel);
        rulesTable.setRowSorter(sorter);
        
        
        rulesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = rulesTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    row = rulesTable.convertRowIndexToModel(row);
                    
                    
                    if (e.getClickCount() == 2) {
                        FingerPrintRule rule = getSelectedRule(row);
                        if (rule != null) {
                            showRuleDialog(rule);
                        }
                    }
                    
                    
                    if (e.getButton() == MouseEvent.BUTTON3) {
                        rulesTable.setRowSelectionInterval(row, row);
                        showPopupMenu(e, row);
                    }
                }
            }
        });
        
        
        JScrollPane scrollPane = new JScrollPane(rulesTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void showPopupMenu(MouseEvent e, int row) {
        JPopupMenu popupMenu = new JPopupMenu();
        
        JMenuItem editItem = new JMenuItem("编辑规则");
        editItem.addActionListener(event -> {
            FingerPrintRule rule = getSelectedRule(row);
            if (rule != null) {
                showRuleDialog(rule);
            }
        });
        
        JMenuItem deleteItem = new JMenuItem("删除规则");
        deleteItem.addActionListener(event -> {
            FingerPrintRule rule = getSelectedRule(row);
            if (rule != null) {
                int confirm = JOptionPane.showConfirmDialog(
                        this,
                        "确定要删除规则 \"" + rule.getCms() + "\" 吗？",
                        "确认删除",
                        JOptionPane.YES_NO_OPTION
                );
                
                if (confirm == JOptionPane.YES_OPTION) {
                    deleteRule(rule);
                }
            }
        });
        
        popupMenu.add(editItem);
        popupMenu.add(deleteItem);
        
        popupMenu.show(e.getComponent(), e.getX(), e.getY());
    }
    
    private FingerPrintRule getSelectedRule(int modelRow) {
        if (modelRow >= 0 && modelRow < fingerprintRules.size()) {
            return fingerprintRules.get(modelRow);
        }
        return null;
    }
    
    private void loadRulesToTable() {
        
        tableModel.setRowCount(0);
        
        
        Set<String> types = new HashSet<>();
        types.add("全部");
        
        
        for (int i = 0; i < fingerprintRules.size(); i++) {
            FingerPrintRule rule = fingerprintRules.get(i);
            
            
            if (rule.getType() != null && !rule.getType().isEmpty()) {
                types.add(rule.getType());
            }
            
            
            Object[] rowData = {
                    i + 1,
                    rule.getCms(),
                    rule.getType(),
                    rule.getMethod(),
                    rule.getLocation(),
                    String.join(", ", rule.getKeyword()),
                    rule.getIsImportant() ? "重要" : "普通"
            };
            tableModel.addRow(rowData);
        }
        
        
        typeFilterComboBox.removeAllItems();
        typeFilterComboBox.addItem("全部");
        for (String type : types) {
            if (!"全部".equals(type)) {
                typeFilterComboBox.addItem(type);
            }
        }
    }
    
    private void filterTable() {
        RowFilter<DefaultTableModel, Object> rf = null;
        
        try {
            List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();
            
            
            String searchText = searchField.getText().trim();
            if (!searchText.isEmpty()) {
                filters.add(RowFilter.regexFilter("(?i)" + searchText));
            }
            
            
            String typeFilter = (String) typeFilterComboBox.getSelectedItem();
            if (typeFilter != null && !"全部".equals(typeFilter)) {
                filters.add(RowFilter.regexFilter("^" + typeFilter + "$", 2));
            }
            
            
            String importantFilter = (String) importantFilterComboBox.getSelectedItem();
            if (importantFilter != null && !"全部".equals(importantFilter)) {
                filters.add(RowFilter.regexFilter("^" + importantFilter + "$", 6));
            }
            
            
            if (!filters.isEmpty()) {
                rf = RowFilter.andFilter(filters);
            }
        } catch (java.util.regex.PatternSyntaxException e) {
            return;
        }
        
        sorter.setRowFilter(rf);
    }
    
    private void showRuleDialog(FingerPrintRule existingRule) {
        
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), 
                existingRule == null ? "添加指纹规则" : "编辑指纹规则", true);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(650, 500);
        dialog.setLocationRelativeTo(this);
        
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        formPanel.setBackground(Color.WHITE);
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        JLabel cmsLabel = new JLabel("CMS名称:");
        formPanel.add(cmsLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JTextField cmsField = new JTextField(20);
        if (existingRule != null) {
            cmsField.setText(existingRule.getCms());
        }
        formPanel.add(cmsField, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        JLabel typeLabel = new JLabel("类型:");
        formPanel.add(typeLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        
        
        JComboBox<String> typeComboBox = new JComboBox<>();
        JTextField typeField = new JTextField(20);
        
        
        Set<String> existingTypes = new HashSet<>();
        for (FingerPrintRule rule : fingerprintRules) {
            if (rule.getType() != null && !rule.getType().isEmpty()) {
                existingTypes.add(rule.getType());
            }
        }
        
        
        for (String type : existingTypes) {
            typeComboBox.addItem(type);
        }
        typeComboBox.addItem("自定义...");
        
        
        JPanel typePanel = new JPanel(new CardLayout());
        typePanel.add(typeComboBox, "combo");
        typePanel.add(typeField, "text");
        
        
        if (existingRule != null && existingRule.getType() != null) {
            String existingType = existingRule.getType();
            boolean typeFound = false;
            
            for (int i = 0; i < typeComboBox.getItemCount(); i++) {
                if (existingType.equals(typeComboBox.getItemAt(i))) {
                    typeComboBox.setSelectedIndex(i);
                    typeFound = true;
                    break;
                }
            }
            
            if (!typeFound) {
                typeComboBox.setSelectedItem("自定义...");
                typeField.setText(existingType);
                CardLayout cl = (CardLayout) typePanel.getLayout();
                cl.show(typePanel, "text");
            }
        }
        
        
        typeComboBox.addActionListener(e -> {
            CardLayout cl = (CardLayout) typePanel.getLayout();
            if ("自定义...".equals(typeComboBox.getSelectedItem())) {
                cl.show(typePanel, "text");
            } else {
                cl.show(typePanel, "combo");
            }
        });
        
        formPanel.add(typePanel, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.0;
        JLabel methodLabel = new JLabel("方法:");
        formPanel.add(methodLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JComboBox<String> methodComboBox = new JComboBox<>(new String[]{"keyword", "faviconhash"});
        if (existingRule != null) {
            methodComboBox.setSelectedItem(existingRule.getMethod());
        }
        formPanel.add(methodComboBox, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        JLabel methodDescLabel = new JLabel("keyword: 基于关键词匹配 | faviconhash: 基于favicon图标哈希值匹配");
        methodDescLabel.setForeground(Color.GRAY);
        formPanel.add(methodDescLabel, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 1;
        gbc.weightx = 0.0;
        JLabel locationLabel = new JLabel("位置:");
        formPanel.add(locationLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JComboBox<String> locationComboBox = new JComboBox<>(new String[]{"body", "header", "title", "favicon"});
        if (existingRule != null) {
            locationComboBox.setSelectedItem(existingRule.getLocation());
        }
        formPanel.add(locationComboBox, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        JLabel locationDescLabel = new JLabel("body: 响应体 | header: 响应头 | title: 网页标题 | favicon: 网站图标");
        locationDescLabel.setForeground(Color.GRAY);
        formPanel.add(locationDescLabel, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 1;
        gbc.weightx = 0.0;
        JLabel keywordLabel = new JLabel("关键词:");
        formPanel.add(keywordLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JTextArea keywordArea = new JTextArea(5, 20);
        keywordArea.setLineWrap(true);
        keywordArea.setWrapStyleWord(true);
        if (existingRule != null && existingRule.getKeyword() != null) {
            keywordArea.setText(String.join("\n", existingRule.getKeyword()));
        }
        JScrollPane keywordScrollPane = new JScrollPane(keywordArea);
        formPanel.add(keywordScrollPane, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 2;
        JLabel keywordDescLabel = new JLabel("每行一个关键词，支持正则表达式");
        keywordDescLabel.setForeground(Color.GRAY);
        formPanel.add(keywordDescLabel, gbc);
        
        
        gbc.gridx = 0;
        gbc.gridy = 8;
        gbc.gridwidth = 1;
        gbc.weightx = 0.0;
        JLabel importantLabel = new JLabel("重要性:");
        formPanel.add(importantLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JCheckBox importantCheckBox = new JCheckBox("标记为重要");
        if (existingRule != null) {
            importantCheckBox.setSelected(existingRule.getIsImportant());
        }
        formPanel.add(importantCheckBox, gbc);
        
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBackground(Color.WHITE);
        
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dialog.dispose());
        
        JButton saveButton = new JButton("保存");
        saveButton.setBackground(PRIMARY_COLOR);
        saveButton.setForeground(Color.WHITE);
        saveButton.addActionListener(e -> {
            
            String cms = cmsField.getText().trim();
            
            
            String type;
            if ("自定义...".equals(typeComboBox.getSelectedItem())) {
                type = typeField.getText().trim();
            } else {
                type = (String) typeComboBox.getSelectedItem();
            }
            
            String method = (String) methodComboBox.getSelectedItem();
            String location = (String) locationComboBox.getSelectedItem();
            String keywordText = keywordArea.getText().trim();
            boolean isImportant = importantCheckBox.isSelected();
            
            
            StringBuilder errorMessage = new StringBuilder();
            
            if (cms.isEmpty()) {
                errorMessage.append("- CMS名称不能为空\n");
            }
            
            if (type == null || type.isEmpty()) {
                errorMessage.append("- 类型不能为空\n");
            }
            
            if (keywordText.isEmpty()) {
                errorMessage.append("- 关键词不能为空\n");
            }
            
            
            if (errorMessage.length() > 0) {
                JOptionPane.showMessageDialog(dialog, 
                        "请修正以下错误：\n" + errorMessage.toString(), 
                        "输入错误", 
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            
            List<String> keywords = new ArrayList<>();
            for (String keyword : keywordText.split("\n")) {
                keyword = keyword.trim();
                if (!keyword.isEmpty()) {
                    keywords.add(keyword);
                }
            }
            
            if (keywords.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "至少需要一个关键词", "输入错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            
            if (existingRule != null) {
                
                int index = fingerprintRules.indexOf(existingRule);
                if (index >= 0) {
                    FingerPrintRule updatedRule = new FingerPrintRule(type, isImportant, cms, method, location, keywords);
                    fingerprintRules.set(index, updatedRule);

                }
            } else {
                
                FingerPrintRule newRule = new FingerPrintRule(type, isImportant, cms, method, location, keywords);
                fingerprintRules.add(newRule);

            }
            
            
            loadRulesToTable();
            
            
            if (onRulesUpdatedListener != null) {
                onRulesUpdatedListener.accept(fingerprintRules);
            }
            
            dialog.dispose();
        });
        
        buttonPanel.add(cancelButton);
        buttonPanel.add(saveButton);
        
        dialog.add(formPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setVisible(true);
    }
    
    private void deleteRule(FingerPrintRule rule) {
        int index = fingerprintRules.indexOf(rule);
        if (index >= 0) {
            fingerprintRules.remove(index);
            loadRulesToTable();
            
            
            if (onRulesUpdatedListener != null) {
                onRulesUpdatedListener.accept(fingerprintRules);
            }
        }
    }
    
    private void saveRulesToFile() {
        try {
            
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("保存指纹规则");
            fileChooser.setSelectedFile(new File("finger-important.json"));
            fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
                @Override
                public boolean accept(File f) {
                    return f.isDirectory() || f.getName().toLowerCase().endsWith(".json");
                }
                
                @Override
                public String getDescription() {
                    return "JSON文件 (*.json)";
                }
            });
            
            int result = fileChooser.showSaveDialog(this);
            if (result != JFileChooser.APPROVE_OPTION) {
                return;
            }
            
            File file = fileChooser.getSelectedFile();
            
            if (!file.getName().toLowerCase().endsWith(".json")) {
                file = new File(file.getAbsolutePath() + ".json");
            }
            
            
            if (file.exists()) {
                int confirm = JOptionPane.showConfirmDialog(
                        this,
                        "文件 " + file.getName() + " 已存在，是否覆盖？",
                        "确认覆盖",
                        JOptionPane.YES_NO_OPTION
                );
                
                if (confirm != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            
            
            Map<String, List<FingerPrintRule>> rulesWrapper = new HashMap<>();
            rulesWrapper.put("fingerprint", fingerprintRules);
            
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String json = gson.toJson(rulesWrapper);
            
            
            try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
                writer.write(json);
            }
            



            
            JOptionPane.showMessageDialog(this, 
                    "规则已成功保存到: " + file.getAbsolutePath() + "\n共 " + fingerprintRules.size() + " 条规则", 
                    "保存成功", 
                    JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "保存规则失败: " + e.getMessage(), "保存失败", JOptionPane.ERROR_MESSAGE);
            callbacks.printError("[!] 保存指纹规则失败: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
        }
    }
    
    
    private void importRulesFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择指纹规则文件");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().toLowerCase().endsWith(".json");
            }
            
            @Override
            public String getDescription() {
                return "JSON文件 (*.json)";
            }
        });
        
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            try (FileReader reader = new FileReader(selectedFile, StandardCharsets.UTF_8)) {
                Gson gson = new Gson();
                Type fingerprintRuleListType = new TypeToken<Map<String, List<FingerPrintRule>>>(){}.getType();
                Map<String, List<FingerPrintRule>> rulesWrapper = gson.fromJson(reader, fingerprintRuleListType);
                List<FingerPrintRule> importedRules = rulesWrapper.get("fingerprint");
                
                if (importedRules != null && !importedRules.isEmpty()) {
                    
                    String[] options = {"替换现有规则", "合并到现有规则", "取消"};
                    int choice = JOptionPane.showOptionDialog(
                            this,
                            "已找到 " + importedRules.size() + " 条规则，您想如何处理？",
                            "导入规则",
                            JOptionPane.YES_NO_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            options,
                            options[1]
                    );
                    
                    if (choice == 0) {
                        
                        fingerprintRules.clear();
                        fingerprintRules.addAll(importedRules);
                        loadRulesToTable();
                        
                        
                        if (onRulesUpdatedListener != null) {
                            onRulesUpdatedListener.accept(fingerprintRules);
                        }
                        
                        JOptionPane.showMessageDialog(
                                this,
                                "已成功导入并替换 " + importedRules.size() + " 条规则",
                                "导入成功",
                                JOptionPane.INFORMATION_MESSAGE
                        );
                    } else if (choice == 1) {
                        
                        int originalSize = fingerprintRules.size();
                        Set<String> existingCmsNames = new HashSet<>();
                        
                        
                        for (FingerPrintRule rule : fingerprintRules) {
                            existingCmsNames.add(rule.getCms().toLowerCase());
                        }
                        
                        
                        int addedCount = 0;
                        for (FingerPrintRule rule : importedRules) {
                            if (!existingCmsNames.contains(rule.getCms().toLowerCase())) {
                                fingerprintRules.add(rule);
                                existingCmsNames.add(rule.getCms().toLowerCase());
                                addedCount++;
                            }
                        }
                        
                        loadRulesToTable();
                        
                        
                        if (onRulesUpdatedListener != null) {
                            onRulesUpdatedListener.accept(fingerprintRules);
                        }
                        
                        JOptionPane.showMessageDialog(
                                this,
                                "已成功合并 " + addedCount + " 条新规则，现共有 " + fingerprintRules.size() + " 条规则",
                                "合并成功",
                                JOptionPane.INFORMATION_MESSAGE
                        );
                    }
                } else {
                    JOptionPane.showMessageDialog(
                            this,
                            "所选文件不包含有效的指纹规则",
                            "导入失败",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(
                        this,
                        "导入规则失败: " + e.getMessage(),
                        "导入失败",
                        JOptionPane.ERROR_MESSAGE
                );
                callbacks.printError("[!] 导入指纹规则失败: " + e.getMessage());
                e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            }
        }
    }

    public void setOnRulesUpdatedListener(Consumer<List<FingerPrintRule>> listener) {
        this.onRulesUpdatedListener = listener;
    }
    
    public List<FingerPrintRule> getFingerprintRules() {
        return new ArrayList<>(fingerprintRules);
    }
}