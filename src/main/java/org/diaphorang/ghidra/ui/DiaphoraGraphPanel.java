/*
 * Diaphora, a binary diffing tool
 * Copyright (c) 2015-2026 Joxean Koret
 * Copyright (c) 2026 ClaudeMonkey (Java port, Claude-Rays/diaphora-ng-ghidra)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.diaphorang.ghidra.ui;

import org.diaphorang.ghidra.util.GraphLayout;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Path2D;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal graph viewer, the equivalent of the IDA graph viewers created by
 * Diaphora (graph_data_t in diaphora-idafree): every node has a text, a
 * background color and a hint. Drag to pan, mouse wheel to zoom, double click
 * on the background to fit the graph in the window.
 */
public class DiaphoraGraphPanel extends JComponent {

    /** Graph to display: node texts, colors (null = theme default), hints and edges. */
    public static final class GraphData {
        public final String title;
        public final List<String> texts = new ArrayList<>();
        public final List<Color> colors = new ArrayList<>();
        public final List<String> hints = new ArrayList<>();
        public final List<int[]> edges = new ArrayList<>();

        public GraphData(String title) {
            this.title = title;
        }

        public int addNode(String text, Color color, String hint) {
            texts.add(text);
            colors.add(color);
            hints.add(hint);
            return texts.size() - 1;
        }
    }

    private static final int PAD = 6;
    private static final int MARGIN = 20;

    private final GraphData data;
    private final Font font = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private double[] widths;
    private double[] heights;
    private GraphLayout.Result layout;

    private double scale = 1.0;
    private double tx = MARGIN;
    private double ty = MARGIN;
    private Point dragStart;
    private boolean fitted;

    public DiaphoraGraphPanel(GraphData data) {
        this.data = data;
        setOpaque(true);
        setToolTipText("");
        setPreferredSize(new Dimension(500, 600));

        MouseAdapter mouse = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                dragStart = e.getPoint();
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (dragStart == null) return;
                tx += e.getX() - dragStart.x;
                ty += e.getY() - dragStart.y;
                dragStart = e.getPoint();
                repaint();
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                dragStart = null;
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && nodeAt(e.getPoint()) < 0) {
                    fitWindow();
                }
            }

            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                double factor = e.getWheelRotation() < 0 ? 1.15 : 1 / 1.15;
                double newScale = Math.max(0.05, Math.min(4.0, scale * factor));
                // zoom around the mouse pointer
                tx = e.getX() - (e.getX() - tx) * (newScale / scale);
                ty = e.getY() - (e.getY() - ty) * (newScale / scale);
                scale = newScale;
                repaint();
            }
        };
        addMouseListener(mouse);
        addMouseMotionListener(mouse);
        addMouseWheelListener(mouse);
        addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (!fitted && getWidth() > 0 && getHeight() > 0) {
                    fitted = true;
                    fitWindow();
                }
            }
        });
    }

    public GraphData getData() {
        return data;
    }

    private void ensureLayout() {
        if (layout != null) return;
        FontMetrics fm = getFontMetrics(font);
        // Measure as painted: antialiased text with fractional metrics may be wider
        java.awt.font.FontRenderContext frc = new java.awt.font.FontRenderContext(null, true, true);
        int n = data.texts.size();
        widths = new double[n];
        heights = new double[n];
        for (int i = 0; i < n; i++) {
            String[] lines = lines(data.texts.get(i));
            double maxW = 0;
            for (String l : lines) {
                maxW = Math.max(maxW, Math.max(fm.stringWidth(l), font.getStringBounds(l, frc).getWidth()));
            }
            widths[i] = Math.ceil(Math.max(maxW, 20)) + 2 * PAD + 2;
            heights[i] = Math.max(lines.length, 1) * fm.getHeight() + 2 * PAD;
        }
        layout = GraphLayout.layout(widths, heights, data.edges);
    }

    private static String[] lines(String text) {
        return text == null || text.isEmpty() ? new String[]{""} : text.split("\n", -1);
    }

    /** viewer_fit_window() */
    public void fitWindow() {
        ensureLayout();
        if (getWidth() <= 0 || getHeight() <= 0) return;
        double gw = layout.width + 2 * MARGIN;
        double gh = layout.height + 2 * MARGIN;
        scale = Math.min(1.0, Math.min(getWidth() / gw, getHeight() / gh));
        tx = (getWidth() - layout.width * scale) / 2;
        ty = MARGIN * scale;
        repaint();
    }

    private int nodeAt(Point p) {
        ensureLayout();
        double gx = (p.x - tx) / scale;
        double gy = (p.y - ty) / scale;
        for (int i = 0; i < widths.length; i++) {
            if (gx >= layout.x[i] && gx <= layout.x[i] + widths[i] &&
                gy >= layout.y[i] && gy <= layout.y[i] + heights[i]) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        int node = nodeAt(e.getPoint());
        if (node < 0) return null;
        String hint = data.hints.get(node);
        return hint == null || hint.isEmpty() ? null : hint;
    }

    @Override
    protected void paintComponent(Graphics g0) {
        ensureLayout();
        Graphics2D g = (Graphics2D) g0.create();
        try {
            Color bg = UIManager.getColor("TextArea.background");
            Color fg = UIManager.getColor("TextArea.foreground");
            if (bg == null) bg = Color.WHITE;
            if (fg == null) fg = Color.BLACK;
            g.setColor(getBackground() != null ? getBackground() : bg);
            g.fillRect(0, 0, getWidth(), getHeight());
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            AffineTransform at = new AffineTransform();
            at.translate(tx, ty);
            at.scale(scale, scale);
            g.transform(at);

            Color edgeColor = new Color(0x40, 0x70, 0xd0);
            g.setStroke(new BasicStroke(1.2f));
            for (double[][] pts : layout.edgePoints) {
                g.setColor(edgeColor);
                Path2D path = new Path2D.Double();
                path.moveTo(pts[0][0], pts[0][1]);
                for (int k = 1; k < pts.length; k++) path.lineTo(pts[k][0], pts[k][1]);
                g.draw(path);
                drawArrow(g, pts[pts.length - 2], pts[pts.length - 1]);
            }

            g.setFont(font);
            FontMetrics fm = g.getFontMetrics();
            for (int i = 0; i < widths.length; i++) {
                int x = (int) Math.round(layout.x[i]);
                int y = (int) Math.round(layout.y[i]);
                int w = (int) Math.round(widths[i]);
                int h = (int) Math.round(heights[i]);
                Color c = data.colors.get(i);
                g.setColor(c != null ? c : bg);
                g.fillRect(x, y, w, h);
                g.setColor(Color.GRAY);
                g.drawRect(x, y, w, h);
                g.setColor(fg);
                int ly = y + PAD + fm.getAscent();
                for (String line : lines(data.texts.get(i))) {
                    g.drawString(line, x + PAD, ly);
                    ly += fm.getHeight();
                }
            }
        } finally {
            g.dispose();
        }
    }

    private static void drawArrow(Graphics2D g, double[] from, double[] to) {
        double angle = Math.atan2(to[1] - from[1], to[0] - from[0]);
        double len = 8;
        Point2D p1 = new Point2D.Double(to[0] - len * Math.cos(angle - Math.PI / 7),
                                        to[1] - len * Math.sin(angle - Math.PI / 7));
        Point2D p2 = new Point2D.Double(to[0] - len * Math.cos(angle + Math.PI / 7),
                                        to[1] - len * Math.sin(angle + Math.PI / 7));
        Path2D head = new Path2D.Double();
        head.moveTo(to[0], to[1]);
        head.lineTo(p1.getX(), p1.getY());
        head.lineTo(p2.getX(), p2.getY());
        head.closePath();
        g.fill(head);
    }
}
