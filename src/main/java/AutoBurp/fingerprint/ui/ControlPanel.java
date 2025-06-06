package AutoBurp.fingerprint.ui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class ControlPanel extends JPanel {
    private JLabel lbRequestCount;
    private JLabel lbSuccessCount;
    private JToggleButton scanToggleButton;
    private boolean isScanEnabled;
    private static final String SCAN_PREF_KEY = "fingerprint_scan_enabled";
    private final IBurpExtenderCallbacks callbacks;
    
    
    private static final Color PRIMARY_COLOR = new Color(60, 141, 188);
    private static final Color ACCENT_COLOR = new Color(0, 166, 90);
    private static final Color LIGHT_TEXT_COLOR = new Color(119, 119, 119);
    private static final Color BORDER_COLOR = new Color(221, 221, 221);
    
    
    private Runnable onRefreshListener;
    private Runnable onClearListener;
    
    
    private Runnable onScanStateChangedListener;
    
    public ControlPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        setLayout(new BorderLayout(10, 0));
        setBackground(Color.WHITE);
        
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(10, 15, 9, 15)
        ));
        
        
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 35, 0)); 
        statsPanel.setBackground(Color.WHITE);
        
        
        Object[] result = createStatPanel("Total Requests Count: ", "0", PRIMARY_COLOR); 
        statsPanel.add((JPanel)result[0]);
        lbRequestCount = (JLabel)result[1];
        
        
        result = createStatPanel("Success Requests Count: ", "0", ACCENT_COLOR); 
        statsPanel.add((JPanel)result[0]);
        lbSuccessCount = (JLabel)result[1];
        
        add(statsPanel, BorderLayout.WEST);
        
        
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10)); 
        actionPanel.setBackground(Color.WHITE);
        
        
        
        String savedPref = callbacks.loadExtensionSetting(SCAN_PREF_KEY);
        isScanEnabled = savedPref != null && savedPref.equals("true");
        
        scanToggleButton = new JToggleButton(isScanEnabled ? "扫描: 开启" : "扫描: 关闭");
        scanToggleButton.setSelected(isScanEnabled);
        scanToggleButton.setBackground(isScanEnabled ? ACCENT_COLOR : new Color(221, 75, 57));
        scanToggleButton.setForeground(Color.WHITE);
        scanToggleButton.setFocusPainted(false);
        scanToggleButton.setBorderPainted(false);
        scanToggleButton.setFont(new Font(scanToggleButton.getFont().getName(), Font.BOLD, 12));
        scanToggleButton.setPreferredSize(new Dimension(100, 25)); 
        
        scanToggleButton.addActionListener(e -> {
            isScanEnabled = scanToggleButton.isSelected();
            scanToggleButton.setText(isScanEnabled ? "扫描: 开启" : "扫描: 关闭");
            scanToggleButton.setBackground(isScanEnabled ? ACCENT_COLOR : new Color(221, 75, 57));
            
            callbacks.saveExtensionSetting(SCAN_PREF_KEY, String.valueOf(isScanEnabled));
            
            
            if (onScanStateChangedListener != null) {
                onScanStateChangedListener.run();
            }
        });
        
        scanToggleButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                scanToggleButton.setBackground(scanToggleButton.isSelected() ? 
                        ACCENT_COLOR.darker() : new Color(221, 75, 57).darker());
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                scanToggleButton.setBackground(scanToggleButton.isSelected() ? 
                        ACCENT_COLOR : new Color(221, 75, 57));
            }
        });
        
        actionPanel.add(scanToggleButton);
        
        
        JButton refreshButton = createStyledButton("刷新", new Color(60, 141, 188));
        refreshButton.addActionListener(e -> {
            if (onRefreshListener != null) {
                onRefreshListener.run();
            }
        });
        actionPanel.add(refreshButton);
        
        
        JButton clearButton = createStyledButton("清空", new Color(221, 75, 57));
        clearButton.addActionListener(e -> {
            if (onClearListener != null) {
                onClearListener.run();
            }
        });
        actionPanel.add(clearButton);
        
        add(actionPanel, BorderLayout.EAST);
    }
    
    
    private Object[] createStatPanel(String title, String value, Color color) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setBackground(Color.WHITE);
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(LIGHT_TEXT_COLOR);
        titleLabel.setFont(new Font(titleLabel.getFont().getName(), Font.PLAIN, 12));
        panel.add(titleLabel);
        
        
        panel.add(Box.createHorizontalStrut(2));
        
        JLabel valueLabel = new JLabel(value);
        valueLabel.setForeground(color);
        valueLabel.setFont(new Font(valueLabel.getFont().getName(), Font.BOLD, 16));
        panel.add(valueLabel);
        
        
        return new Object[]{panel, valueLabel};
    }
    
    private JButton createStyledButton(String text, Color color) {
        JButton button = new JButton(text);
        button.setBackground(color);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setFont(new Font(button.getFont().getName(), Font.BOLD, 12));
        button.setPreferredSize(new Dimension(80, 30)); 
        
        
        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                button.setBackground(color.darker());
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                button.setBackground(color);
            }
        });
        
        return button;
    }
    
    public void setRequestCount(int count) {
        lbRequestCount.setText(String.valueOf(count));
    }
    
    public void setSuccessCount(int count) {
        lbSuccessCount.setText(String.valueOf(count));
    }
    
    public boolean isScanEnabled() {
        return isScanEnabled;
    }
    
    public void setOnRefreshListener(Runnable listener) {
        this.onRefreshListener = listener;
    }
    
    public void setOnClearListener(Runnable listener) {
        this.onClearListener = listener;
    }
    
    
    public void setOnScanStateChangedListener(Runnable listener) {
        this.onScanStateChangedListener = listener;
    }
}