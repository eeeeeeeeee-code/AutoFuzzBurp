package AutoBurp.fingerprint.ui;

import java.awt.*;

/**
 * 自动换行的FlowLayout实现
 * 当容器宽度不足时，组件会自动换行显示
 */
public class WrapLayout extends FlowLayout {

    public WrapLayout(int align, int hgap, int vgap) {
        super(align, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        Dimension minimum = layoutSize(target, false);
        minimum.width -= (getHgap() + 1);
        return minimum;
    }

    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            
            int targetWidth = target.getSize().width;

            
            if (targetWidth == 0) {
                targetWidth = Integer.MAX_VALUE;
            }

            int hgap = getHgap();
            int vgap = getVgap();
            Insets insets = target.getInsets();
            int horizontalInsetsAndGap = insets.left + insets.right + (hgap * 2);

            
            int maxWidth = targetWidth - horizontalInsetsAndGap;

            
            int x = 0;
            int y = insets.top;
            int rowHeight = 0;

            
            int nmembers = target.getComponentCount();

            for (int i = 0; i < nmembers; i++) {
                Component m = target.getComponent(i);
                if (m.isVisible()) {
                    Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();

                    
                    if (x > 0 && x + d.width > maxWidth) {
                        x = 0;
                        y += rowHeight + vgap;
                        rowHeight = 0;
                    }

                    
                    if (x > 0) {
                        x += hgap;
                    }
                    x += d.width;
                    rowHeight = Math.max(rowHeight, d.height);
                }
            }

            
            y += rowHeight + insets.bottom;

            return new Dimension(targetWidth, y);
        }
    }
}