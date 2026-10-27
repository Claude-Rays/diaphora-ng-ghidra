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

import docking.DialogComponentProvider;
import org.diaphorang.ghidra.util.SideBySideDiff;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * Side-by-side synchronized diff dialog for comparing pseudo-code or assembly.
 */
public class DiaphoraDiffDialog extends DialogComponentProvider {

    private final String text1;
    private final String text2;
    private final UnaryOperator<String> key;
    private final List<DiaphoraNote> notes;

    /** side_by_side_view() of two buffers, as CHtmlDiff. */
    public DiaphoraDiffDialog(String title, String text1, String text2) {
        this(title, text1, text2, null, List.of());
    }

    /**
     * Diaphora-ng: the same with the lines compared through 'key' (null: as
     * they are) and 'notes' shown above both sides (the Claude diff).
     */
    public DiaphoraDiffDialog(String title, String text1, String text2, UnaryOperator<String> key,
                              List<DiaphoraNote> notes) {
        super(title, false, true, true, false);
        this.text1 = text1 != null ? text1 : "";
        this.text2 = text2 != null ? text2 : "";
        this.key = key;
        this.notes = notes != null ? notes : List.of();
        buildUI();
    }

    private void buildUI() {
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(new EmptyBorder(8, 8, 8, 8));
        mainPanel.setPreferredSize(new Dimension(1100, 750));

        List<String> lines1 = Arrays.asList(text1.split("\n"));
        List<String> lines2 = Arrays.asList(text2.split("\n"));

        List<SideBySideDiff.Row> rows = SideBySideDiff.diff(lines1, lines2, key);

        JTextPane pane1 = createTextPane();
        JTextPane pane2 = createTextPane();

        populatePanes(rows, Math.max(lines1.size(), lines2.size()), pane1, pane2);

        JScrollPane scroll1 = new JScrollPane(pane1);
        JScrollPane scroll2 = new JScrollPane(pane2);

        // Synchronize vertical scrollbars
        scroll1.getVerticalScrollBar().setModel(scroll2.getVerticalScrollBar().getModel());

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scroll1, scroll2);
        splitPane.setResizeWeight(0.5);
        if (notes.isEmpty()) {
            mainPanel.add(splitPane, BorderLayout.CENTER);
        } else {
            JTextPane header = createTextPane();
            for (DiaphoraNote n : notes) {
                appendText(header.getStyledDocument(), "// " + n.text() + "\n", n.attributes());
            }
            header.setCaretPosition(0);
            JScrollPane headerScroll = new JScrollPane(header);
            headerScroll.setPreferredSize(new Dimension(1100, 220));
            JSplitPane vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT, headerScroll, splitPane);
            vertical.setResizeWeight(0.25);
            mainPanel.add(vertical, BorderLayout.CENTER);
        }

        addWorkPanel(mainPanel);
        addDismissButton();
    }

    private JTextPane createTextPane() {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return pane;
    }

    /**
     * Rows as CHtmlDiff (difflib._mdiff) shows them: similar lines side by side
     * with only the changed characters marked (yellow changed, green added, red
     * deleted) and lines without a close match fully marked.
     */
    private void populatePanes(List<SideBySideDiff.Row> rows, int totalLines, JTextPane pane1, JTextPane pane2) {
        StyledDocument doc1 = pane1.getStyledDocument();
        StyledDocument doc2 = pane2.getStyledDocument();

        Color background = pane1.getBackground();
        Map<Character, Color> colors = Map.of(
            '+', DiaphoraColors.diffAdded(background),
            '^', DiaphoraColors.diffChanged(background),
            '-', DiaphoraColors.diffSubtracted(background));

        int width = String.valueOf(totalLines).length();
        for (SideBySideDiff.Row row : rows) {
            appendRow(doc1, row.lno, row.ltxt, row.changed ? row.lspans : List.of(), width, colors);
            appendRow(doc2, row.rno, row.rtxt, row.changed ? row.rspans : List.of(), width, colors);
        }
    }

    private void appendRow(StyledDocument doc, int lineNo, String text, List<SideBySideDiff.Span> spans,
                           int width, Map<Character, Color> colors) {
        SimpleAttributeSet lineNoAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(lineNoAttrs, Color.GRAY);
        String prefix = lineNo != 0 ? String.format("%" + width + "d ", lineNo) : " ".repeat(width + 1);
        appendText(doc, prefix, lineNoAttrs);

        int pos = 0;
        for (SideBySideDiff.Span span : spans) {
            int start = Math.min(span.start, text.length());
            int end = Math.min(span.end, text.length());
            if (start > pos) {
                appendText(doc, text.substring(pos, start), null);
            }
            if (end > start) {
                SimpleAttributeSet attrs = new SimpleAttributeSet();
                StyleConstants.setBackground(attrs, colors.get(span.kind));
                appendText(doc, text.substring(start, end), attrs);
            }
            pos = Math.max(pos, end);
        }
        if (pos < text.length()) {
            appendText(doc, text.substring(pos), null);
        }
        appendText(doc, "\n", null);
    }

    private void appendText(StyledDocument doc, String text, AttributeSet attrs) {
        try {
            doc.insertString(doc.getLength(), text, attrs != null ? attrs : SimpleAttributeSet.EMPTY);
        } catch (BadLocationException ignored) {
        }
    }
}
