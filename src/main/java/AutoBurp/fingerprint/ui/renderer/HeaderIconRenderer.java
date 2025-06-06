package AutoBurp.fingerprint.ui.renderer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.Set;
import java.util.HashSet;

/**
 * 表头渲染器，支持显示排序图标和过滤图标
 * 优化后支持动态配置哪些列显示过滤图标
 */
public class HeaderIconRenderer extends DefaultTableCellRenderer {
    private static final Color HEADER_BG_COLOR = new Color(245, 245, 245);
    private static final Color HEADER_TEXT_COLOR = new Color(51, 51, 51);
    private static final Color HEADER_BORDER_COLOR = new Color(221, 221, 221);
    private static final Color ICON_COLOR = new Color(119, 119, 119);
    
    
    private final Set<Integer> filterColumns = new HashSet<>();
    
    public HeaderIconRenderer() {
        setHorizontalAlignment(LEFT);
        setHorizontalTextPosition(LEFT);
        setVerticalAlignment(CENTER);
        setOpaque(true);
    }
    
    /**
     * 添加需要显示过滤图标的列
     * @param columnIndex 列索引
     */
    public void addFilterColumn(int columnIndex) {
        filterColumns.add(columnIndex);
    }
    
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                  boolean isSelected, boolean hasFocus,
                                                  int row, int column) {
        JTableHeader header = table.getTableHeader();
        if (header != null) {
            setForeground(HEADER_TEXT_COLOR);
            setBackground(HEADER_BG_COLOR);
            setFont(header.getFont());
        }
        
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 1, HEADER_BORDER_COLOR),
                new EmptyBorder(5, 5, 5, 5)
        ));
        
        
        if (filterColumns.contains(column)) {
            setIcon(createFilterIcon());
            setIconTextGap(5);
        } else {
            setIcon(null);
        }
        
        setText(value == null ? "" : value.toString());
        
        return this;
    }
    
    private Icon createFilterIcon() {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2d = (Graphics2D) g.create();
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                int size = 8;
                int[] xPoints = {x, x + size, x + size/2};
                int[] yPoints = {y, y, y + size/2};
                
                g2d.setColor(ICON_COLOR);
                g2d.fillPolygon(xPoints, yPoints, 3);
                
                g2d.dispose();
            }
            
            @Override
            public int getIconWidth() {
                return 10;
            }
            
            @Override
            public int getIconHeight() {
                return 10;
            }
        };
    }
}