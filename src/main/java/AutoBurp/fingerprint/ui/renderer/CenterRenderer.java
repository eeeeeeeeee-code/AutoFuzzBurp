package AutoBurp.fingerprint.ui.renderer;

import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * 居中显示的表格单元格渲染器
 */
public class CenterRenderer extends DefaultTableCellRenderer {
    public CenterRenderer() {
        setHorizontalAlignment(CENTER);
    }
    
    @Override
    public Component getTableCellRendererComponent(javax.swing.JTable table, Object value,
                                                  boolean isSelected, boolean hasFocus,
                                                  int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        if (isSelected) {
            c.setBackground(new Color(66, 139, 202));
            c.setForeground(Color.WHITE);
        } else {
            
            if (row % 2 == 0) {
                c.setBackground(Color.WHITE);
            } else {
                c.setBackground(new Color(249, 249, 249));
            }
            c.setForeground(new Color(51, 51, 51));
        }
        
        return c;
    }
}