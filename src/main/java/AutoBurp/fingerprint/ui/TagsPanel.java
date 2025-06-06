package AutoBurp.fingerprint.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class TagsPanel extends JPanel {
    private JPanel tagsPanel;
    private JLabel currentSelectedLabel = null;
    private final Map<String, JLabel> resultLabels = new HashMap<>();
    private Consumer<String> onTagSelectedListener;
    
    
    private static final Color PRIMARY_COLOR = new Color(60, 141, 188);
    private static final Color TEXT_COLOR = new Color(51, 51, 51);
    private static final Color BORDER_COLOR = new Color(221, 221, 221);
    private static final Color HOVER_COLOR = new Color(240, 248, 255);
    
    public TagsPanel() {
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR), 
                new EmptyBorder(8, 15, 8, 15) 
        ));
        
        tagsPanel = new JPanel();
        tagsPanel.setLayout(new WrapLayout(FlowLayout.LEFT, 10, 3)); 
        tagsPanel.setBackground(Color.WHITE);
        
        
        JLabel allLabel = createTagLabel("全部");
        allLabel.setBackground(PRIMARY_COLOR);
        allLabel.setForeground(Color.WHITE);
        allLabel.setOpaque(true);
        currentSelectedLabel = allLabel;
        tagsPanel.add(allLabel);
        
        
        JScrollPane tagsScrollPane = new JScrollPane(tagsPanel);
        tagsScrollPane.setBorder(null);
        
        tagsScrollPane.setPreferredSize(new Dimension(0, 35));
        tagsScrollPane.setMinimumSize(new Dimension(0, 35));
        
        tagsScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        tagsScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        tagsScrollPane.getViewport().setBackground(Color.WHITE);
        
        add(tagsScrollPane, BorderLayout.CENTER);
        
        
        setMinimumSize(new Dimension(0, 50));
        setPreferredSize(new Dimension(0, 50));
    }
    
    private JLabel createTagLabel(String text) {
        JLabel label = new JLabel(text);
        label.setOpaque(false);
        label.setForeground(TEXT_COLOR);
        label.setFont(new Font(label.getFont().getName(), Font.PLAIN, 13));
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(3, 8, 3, 8) 
        ));
        
        
        label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (label != currentSelectedLabel) {
                    label.setBackground(HOVER_COLOR);
                    label.setOpaque(true);
                }
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                if (label != currentSelectedLabel) {
                    label.setOpaque(false);
                }
            }
            
            @Override
            public void mouseClicked(MouseEvent e) {
                
                if (e.getButton() == MouseEvent.BUTTON1) {
                    if (currentSelectedLabel != null) {
                        currentSelectedLabel.setBackground(null);
                        currentSelectedLabel.setForeground(TEXT_COLOR);
                        currentSelectedLabel.setOpaque(false);
                    }
                    
                    label.setBackground(PRIMARY_COLOR);
                    label.setForeground(Color.WHITE);
                    label.setOpaque(true);
                    currentSelectedLabel = label;
                    
                    
                    if (onTagSelectedListener != null) {
                        String type = label.getText();
                        onTagSelectedListener.accept(type.equals("全部") ? null : type);
                    }
                }
                
                else if (e.getButton() == MouseEvent.BUTTON3 && onRightClickListener != null) {
                    onRightClickListener.accept(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        
        return label;
    }
    
    public void addTag(String type) {
        if (!resultLabels.containsKey(type)) {
            JLabel typeLabel = createTagLabel(type);
            tagsPanel.add(typeLabel);
            resultLabels.put(type, typeLabel);
            tagsPanel.revalidate();
            tagsPanel.repaint();
        }
    }
    
    public void clearTags() {
        tagsPanel.removeAll();
        JLabel allLabel = createTagLabel("全部");
        allLabel.setBackground(PRIMARY_COLOR);
        allLabel.setForeground(Color.WHITE);
        allLabel.setOpaque(true);
        tagsPanel.add(allLabel);
        currentSelectedLabel = allLabel;
        
        resultLabels.clear();
        
        tagsPanel.revalidate();
        tagsPanel.repaint();
    }
    
    public void selectTag(String type) {
        if (currentSelectedLabel != null) {
            currentSelectedLabel.setBackground(null);
            currentSelectedLabel.setForeground(TEXT_COLOR);
            currentSelectedLabel.setOpaque(false);
        }
        
        JLabel targetLabel = null;
        if (type == null || type.equals("全部")) {
            
            for (Component component : tagsPanel.getComponents()) {
                if (component instanceof JLabel && ((JLabel) component).getText().equals("全部")) {
                    targetLabel = (JLabel) component;
                    break;
                }
            }
        } else {
            targetLabel = resultLabels.get(type);
        }
        
        if (targetLabel != null) {
            targetLabel.setBackground(PRIMARY_COLOR);
            targetLabel.setForeground(Color.WHITE);
            targetLabel.setOpaque(true);
            currentSelectedLabel = targetLabel;
        }
    }
    
    public void setOnTagSelectedListener(Consumer<String> listener) {
        this.onTagSelectedListener = listener;
    }
    
    
    private TriConsumer<Component, Integer, Integer> onRightClickListener;

    
    @FunctionalInterface
    public interface TriConsumer<T, U, V> {
        void accept(T t, U u, V v);
    }
}