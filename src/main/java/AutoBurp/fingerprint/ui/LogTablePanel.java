package AutoBurp.fingerprint.ui;

import AutoBurp.fingerprint.model.TableLogModel;
import AutoBurp.fingerprint.ui.renderer.CenterRenderer;
import AutoBurp.fingerprint.ui.renderer.HeaderIconRenderer;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;


@SuppressWarnings("unchecked")
public class LogTablePanel extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private JTable logTable;
    private DefaultTableModel logTableModel;
    private final List<TableLogModel> logEntries;
    private final Set<String> uniqueTypes;
    private Consumer<TableLogModel> onRowSelectedListener;
    private Consumer<String> typeFilterChangedListener;
    
    
    private final Object tableLock = new Object();
    private volatile boolean isUpdating = false;
    
    
    private static final Color BACKGROUND_COLOR = new Color(252, 252, 252);
    private static final Color HEADER_BACKGROUND = new Color(245, 247, 250);
    private static final Color HEADER_FOREGROUND = new Color(80, 90, 108);
    private static final Color BORDER_COLOR = new Color(230, 235, 240);
    private static final Color ALTERNATE_ROW_COLOR = new Color(248, 250, 252);
    private static final Color TEXT_COLOR = new Color(60, 70, 85);
    private static final Color SELECTION_BACKGROUND = new Color(66, 139, 202, 160);
    private static final Color SELECTION_FOREGROUND = Color.WHITE;
    
    
    private static final int CORNER_RADIUS = 8;

    public LogTablePanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, 
                         List<TableLogModel> logEntries, Set<String> uniqueTypes) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.logEntries = logEntries;
        this.uniqueTypes = uniqueTypes;
        
        setLayout(new BorderLayout(0, 0));
        setBackground(BACKGROUND_COLOR);
        setBorder(new EmptyBorder(12, 12, 12, 12));
        
        
        createLogTable();
        
        
        JScrollPane tableScrollPane = new JScrollPane(logTable) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(BACKGROUND_COLOR);
                g2.fillRoundRect(0, 0, getWidth()-1, getHeight()-1, CORNER_RADIUS, CORNER_RADIUS);
                
                
                for (int i = 0; i < 3; i++) {
                    g2.setColor(new Color(0, 0, 0, 3 - i));
                    g2.drawRoundRect(i, i, getWidth() - 1 - 2*i, getHeight() - 1 - 2*i, CORNER_RADIUS, CORNER_RADIUS);
                }
                g2.dispose();
            }
        };
        
        tableScrollPane.setBorder(null);
        tableScrollPane.getViewport().setBackground(BACKGROUND_COLOR);
        tableScrollPane.setOpaque(false);
        tableScrollPane.getViewport().setOpaque(false);
        
        
        JScrollBar verticalScrollBar = tableScrollPane.getVerticalScrollBar();
        verticalScrollBar.setUI(new BasicScrollBarUI() {
            @Override
            protected void configureScrollBarColors() {
                this.thumbColor = new Color(180, 190, 200, 120);
                this.trackColor = BACKGROUND_COLOR;
            }
            
            @Override
            protected JButton createDecreaseButton(int orientation) {
                return createZeroButton();
            }
            
            @Override
            protected JButton createIncreaseButton(int orientation) {
                return createZeroButton();
            }
            
            private JButton createZeroButton() {
                JButton button = new JButton();
                button.setPreferredSize(new Dimension(0, 0));
                button.setMinimumSize(new Dimension(0, 0));
                button.setMaximumSize(new Dimension(0, 0));
                return button;
            }
            
            @Override
            protected void paintThumb(Graphics g, JComponent c, Rectangle thumbBounds) {
                if (thumbBounds.isEmpty() || !scrollbar.isEnabled()) {
                    return;
                }
                
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(thumbColor);
                g2.fillRoundRect(thumbBounds.x + 2, thumbBounds.y + 2, 
                                thumbBounds.width - 4, thumbBounds.height - 4, 8, 8);
                g2.dispose();
            }
        });
        
        verticalScrollBar.setPreferredSize(new Dimension(8, 0));
        
        add(tableScrollPane, BorderLayout.CENTER);
    }
    
    private void createLogTable() {
        
        logTableModel = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 7) { 
                    return Boolean.class;
                }
                return String.class;
            }
        };
        
        
        logTableModel.addColumn("ID");
        logTableModel.addColumn("URL");
        logTableModel.addColumn("Status");
        logTableModel.addColumn("Title");
        logTableModel.addColumn("Method");
        logTableModel.addColumn("Result");
        logTableModel.addColumn("Type");
        logTableModel.addColumn("Important");
        logTableModel.addColumn("Match Pattern");
        logTableModel.addColumn("Time");
        
        
        logTable = new JTable(logTableModel) {
            
            @Override
            public void paint(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                super.paint(g2);
                g2.dispose();
            }
        };
        
        
        logTable.setShowGrid(false);
        logTable.setIntercellSpacing(new Dimension(0, 0));
        logTable.setRowHeight(28); 
        logTable.setBackground(BACKGROUND_COLOR);
        logTable.setForeground(TEXT_COLOR);
        
        
        logTable.setSelectionBackground(SELECTION_BACKGROUND);
        logTable.setSelectionForeground(SELECTION_FOREGROUND);
        
        logTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logTable.setFont(new Font(logTable.getFont().getName(), Font.PLAIN, 12));
        
        
        JTableHeader header = logTable.getTableHeader();
        header.setBackground(HEADER_BACKGROUND);
        header.setForeground(HEADER_FOREGROUND);
        header.setFont(new Font(header.getFont().getName(), Font.PLAIN, 12));
        header.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_COLOR));
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 36)); 
        
        
        logTable.getColumnModel().getColumn(0).setPreferredWidth(50);  
        logTable.getColumnModel().getColumn(1).setPreferredWidth(300); 
        logTable.getColumnModel().getColumn(2).setPreferredWidth(60);  
        logTable.getColumnModel().getColumn(3).setPreferredWidth(150); 
        logTable.getColumnModel().getColumn(4).setPreferredWidth(60);  
        logTable.getColumnModel().getColumn(5).setPreferredWidth(150); 
        logTable.getColumnModel().getColumn(6).setPreferredWidth(100); 
        logTable.getColumnModel().getColumn(7).setPreferredWidth(80);  
        logTable.getColumnModel().getColumn(8).setPreferredWidth(200); 
        logTable.getColumnModel().getColumn(9).setPreferredWidth(150); 
        
        
        DefaultTableCellRenderer centerRenderer = new CenterRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                ((JComponent)c).setBorder(new EmptyBorder(0, 8, 0, 8)); 
                return c;
            }
        };
        centerRenderer.setBackground(BACKGROUND_COLOR);
        
        
        logTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        logTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        logTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        
        
        HeaderIconRenderer headerRenderer = new HeaderIconRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                ((JComponent)c).setBorder(new EmptyBorder(0, 8, 0, 8)); 
                return c;
            }
        };
        
        
        headerRenderer.addFilterColumn(6); 
        headerRenderer.addFilterColumn(7); 
        header.setDefaultRenderer(headerRenderer);
        
        
        header.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int columnIndex = logTable.getColumnModel().getColumnIndexAtX(e.getX());
                
                if (columnIndex == 6) { 
                    showTypeFilterMenu(e);
                } else if (columnIndex == 7) { 
                    showImportantFilterMenu(e);
                }
            }
        });
        
        
        logTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = logTable.getSelectedRow();
                if (selectedRow != -1) {
                    try {
                        
                        int modelRow = logTable.convertRowIndexToModel(selectedRow);
                        int id = Integer.parseInt(logTableModel.getValueAt(modelRow, 0).toString());
                        
                        
                        for (TableLogModel entry : logEntries) {
                            if (entry.getId() == id) {
                                
                                if (entry.getHttpRequestResponse() != null) {
                                    if (onRowSelectedListener != null) {
                                        onRowSelectedListener.accept(entry);
                                    }
                                }
                                break;
                            }
                        }
                    } catch (Exception ex) {
                        
                        System.err.println("处理行选择时出错: " + ex.getMessage());
                    }
                }
            }
        });
        
        
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(logTableModel);
        logTable.setRowSorter(sorter);
        
        
        logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(
                        table, value, isSelected, hasFocus, row, column);
                
                if (isSelected) {
                    c.setBackground(SELECTION_BACKGROUND);
                    c.setForeground(SELECTION_FOREGROUND);
                } else {
                    
                    if (row % 2 == 0) {
                        c.setBackground(BACKGROUND_COLOR);
                    } else {
                        c.setBackground(ALTERNATE_ROW_COLOR);
                    }
                    c.setForeground(TEXT_COLOR);
                }
                
                
                ((JComponent) c).setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                
                return c;
            }
        });
        
        
        logTable.setDefaultRenderer(Boolean.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                
                JCheckBox checkBox = new JCheckBox();
                checkBox.setHorizontalAlignment(SwingConstants.CENTER);
                checkBox.setSelected(value != null && (Boolean) value);
                
                if (isSelected) {
                    checkBox.setBackground(SELECTION_BACKGROUND);
                    checkBox.setForeground(SELECTION_FOREGROUND);
                } else {
                    if (row % 2 == 0) {
                        checkBox.setBackground(BACKGROUND_COLOR);
                    } else {
                        checkBox.setBackground(ALTERNATE_ROW_COLOR);
                    }
                    checkBox.setForeground(TEXT_COLOR);
                }
                
                return checkBox;
            }
        });
    }
    
    private void showTypeFilterMenu(MouseEvent e) {
        JPopupMenu filterMenu = createStyledPopupMenu();
        
        
        JMenuItem allItem = createStyledMenuItem("全部");
        allItem.addActionListener(e1 -> {
            filterTable(null, null);
            if (typeFilterChangedListener != null) {
                typeFilterChangedListener.accept("全部");
            }
        });
        filterMenu.add(allItem);
        
        filterMenu.add(new JSeparator()); 
        
        
        for (String type : uniqueTypes) {
            JMenuItem menuItem = createStyledMenuItem(type);
            menuItem.addActionListener(e1 -> {
                filterTable(type, null);
                if (typeFilterChangedListener != null) {
                    typeFilterChangedListener.accept(type);
                }
            });
            filterMenu.add(menuItem);
        }
        
        showStyledPopupMenu(filterMenu, e);
    }
    
    private void showImportantFilterMenu(MouseEvent e) {
        JPopupMenu filterMenu = createStyledPopupMenu();
        
        List<String> importantOptions = Arrays.asList("全部", "重点", "普通");
        
        for (String option : importantOptions) {
            JMenuItem menuItem = createStyledMenuItem(option);
            menuItem.addActionListener(e1 -> {
                Boolean important = null;
                if (option.equals("重点")) {
                    important = true;
                } else if (option.equals("普通")) {
                    important = false;
                }
                
                filterTable(null, important);
            });
            filterMenu.add(menuItem);
        }
        
        showStyledPopupMenu(filterMenu, e);
    }
    
    
    private JPopupMenu createStyledPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        menu.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR, 1),
            BorderFactory.createEmptyBorder(4, 0, 4, 0)
        ));
        menu.setBackground(BACKGROUND_COLOR);
        return menu;
    }
    
    
    private JMenuItem createStyledMenuItem(String text) {
        JMenuItem item = new JMenuItem(text);
        item.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        item.setBackground(BACKGROUND_COLOR);
        item.setForeground(TEXT_COLOR);
        
        
        item.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                item.setBackground(new Color(240, 245, 250));
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                item.setBackground(BACKGROUND_COLOR);
            }
        });
        
        return item;
    }
    
    
    private void showStyledPopupMenu(JPopupMenu menu, MouseEvent e) {
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    @SuppressWarnings("unchecked")
    private void sortTable(String column) {
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) logTable.getRowSorter();
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();
        
        int columnIndex = -1;
        switch (column) {
            case "Type":
                columnIndex = 6;
                break;
            case "Result":
                columnIndex = 5;
                break;
            case "Important":
                columnIndex = 7;
                break;
            case "Time":
                columnIndex = 8;
                break;
        }
        
        if (columnIndex != -1) {
            
            List<? extends RowSorter.SortKey> currentKeys = sorter.getSortKeys();
            SortOrder order = SortOrder.ASCENDING;
            
            if (!currentKeys.isEmpty() && currentKeys.get(0).getColumn() == columnIndex) {
                
                order = currentKeys.get(0).getSortOrder() == SortOrder.ASCENDING ? 
                        SortOrder.DESCENDING : SortOrder.ASCENDING;
            }
            
            sortKeys.add(new RowSorter.SortKey(columnIndex, order));
            sorter.setSortKeys(sortKeys);
            sorter.sort();
        }
    }

    public void setOnTypeFilterChangedListener(Consumer<String> listener) {
        this.typeFilterChangedListener = listener;
    }
    
    public void setOnRowSelectedListener(Consumer<TableLogModel> listener) {
        this.onRowSelectedListener = listener;
    }
    
    
    private void updateTableInternal() {
        synchronized (tableLock) {
            if (isUpdating) {
                return; 
            }
            
            isUpdating = true;
            try {
                
                int selectedId = -1;
                int selectedRow = logTable.getSelectedRow();
                if (selectedRow != -1) {
                    try {
                        int modelRow = logTable.convertRowIndexToModel(selectedRow);
                        if (modelRow >= 0 && modelRow < logTableModel.getRowCount()) {
                            Object idValue = logTableModel.getValueAt(modelRow, 0);
                            if (idValue != null) {
                                selectedId = Integer.parseInt(idValue.toString());
                            }
                        }
                    } catch (Exception e) {
                        
                    }
                }
                
                
                logTableModel.setRowCount(0);
                
                
                List<Object[]> rowsToAdd = new ArrayList<>();
                for (TableLogModel entry : logEntries) {
                    
                    String url = entry.getUrl();
                    String fullUrl = getFullUrl(entry, url);
                    
                    rowsToAdd.add(new Object[]{
                        entry.getId(),
                        fullUrl, 
                        entry.getStatus(),
                        entry.getTitle(),
                        entry.getMethod(),
                        entry.getResult(),
                        entry.getType(),
                        entry.getIsImportant(),
                        entry.getMatchPattern(), 
                        entry.getTime()
                    });
                }
                
                
                for (Object[] row : rowsToAdd) {
                    logTableModel.addRow(row);
                }
                
                
                if (selectedId != -1) {
                    for (int i = 0; i < logTableModel.getRowCount(); i++) {
                        try {
                            Object idValue = logTableModel.getValueAt(i, 0);
                            if (idValue != null && Integer.parseInt(idValue.toString()) == selectedId) {
                                int viewRow = logTable.convertRowIndexToView(i);
                                if (viewRow >= 0) {
                                    logTable.setRowSelectionInterval(viewRow, viewRow);
                                    logTable.scrollRectToVisible(logTable.getCellRect(viewRow, 0, true));
                                    break;
                                }
                            }
                        } catch (Exception e) {
                            
                        }
                    }
                } else if (logTableModel.getRowCount() > 0) {
                    
                    int lastRow = logTable.convertRowIndexToView(logTableModel.getRowCount() - 1);
                    if (lastRow >= 0) {
                        logTable.scrollRectToVisible(logTable.getCellRect(lastRow, 0, true));
                    }
                }
            } finally {
                isUpdating = false;
            }
        }
    }
    
    
    public void safeUpdateTable() {
        if (SwingUtilities.isEventDispatchThread()) {
            updateTableInternal();
        } else {
            SwingUtilities.invokeLater(this::updateTableInternal);
        }
    }

    
    public void filterTable(String type, Boolean important) {
        if (SwingUtilities.isEventDispatchThread()) {
            filterTableInternal(type, important);
        } else {
            SwingUtilities.invokeLater(() -> filterTableInternal(type, important));
        }
    }
    
    
    private void filterTableInternal(String type, Boolean important) {
        synchronized (tableLock) {
            DefaultTableModel model = (DefaultTableModel) logTable.getModel();
            model.setRowCount(0); 
            
            
            List<Object[]> rowsToAdd = new ArrayList<>();
            
            for (TableLogModel entry : logEntries) {
                boolean typeMatch = type == null || entry.getType().equals(type);
                boolean importantMatch = important == null || entry.getIsImportant() == important;
                
                if (typeMatch && importantMatch) {
                    
                    String url = entry.getUrl();
                    String fullUrl = getFullUrl(entry, url);
                    
                    
                    rowsToAdd.add(new Object[]{
                        entry.getId(),
                        fullUrl,  
                        entry.getStatus(),
                        entry.getTitle(),
                        entry.getMethod(),
                        entry.getResult(),
                        entry.getType(),
                        entry.getIsImportant(),
                        entry.getMatchPattern(), 
                        entry.getTime()
                    });
                }
            }
            
            
            for (Object[] row : rowsToAdd) {
                model.addRow(row);
            }
        }
    }

    
    private String getFullUrl(TableLogModel entry, String url) {
        if (url == null || url.isEmpty()) {
            return "";
        }
        
        
        if (url.startsWith("http://") || url.startsWith("https://")) {
            return url;
        }
        
        
        try {
            int index = entry.getRequestResponseIndex();
            if (index >= 0) {
                IHttpRequestResponse[] proxyHistory = callbacks.getProxyHistory();
                if (proxyHistory != null && index < proxyHistory.length) {
                    IHttpRequestResponse requestResponse = proxyHistory[index];
                    if (requestResponse != null && requestResponse.getHttpService() != null) {
                        String protocol = requestResponse.getHttpService().getProtocol();
                        String host = requestResponse.getHttpService().getHost();
                        int port = requestResponse.getHttpService().getPort();
                        
                        StringBuilder fullUrlBuilder = new StringBuilder();
                        fullUrlBuilder.append(protocol).append("://").append(host);
                        
                        if ((protocol.equals("http") && port != 80) || 
                            (protocol.equals("https") && port != 443)) {
                            fullUrlBuilder.append(":").append(port);
                        }
                        
                        if (!url.startsWith("/")) {
                            fullUrlBuilder.append("/");
                        }
                        
                        fullUrlBuilder.append(url);
                        return fullUrlBuilder.toString();
                    }
                }
            }
        } catch (Exception e) {
            
            System.err.println("构建完整URL时出错: " + e.getMessage());
        }
        
        
        return url;
    }

    public void clearTable() {
        if (SwingUtilities.isEventDispatchThread()) {
            synchronized (tableLock) {
                logTableModel.setRowCount(0);
            }
        } else {
            SwingUtilities.invokeLater(() -> {
                synchronized (tableLock) {
                    logTableModel.setRowCount(0);
                }
            });
        }
    }
}