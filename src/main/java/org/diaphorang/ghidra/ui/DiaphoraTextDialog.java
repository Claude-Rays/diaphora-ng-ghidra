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
import java.util.function.UnaryOperator;

/**
 * show_text_view(): a read only source viewer, used by "Show assembly",
 * "Show pseudo-code" (numbered_source) and by the patch views (unified_view).
 */
public class DiaphoraTextDialog extends DialogComponentProvider {

    private final JTextPane pane = new JTextPane();

    private DiaphoraTextDialog(String title) {
        super(title, false, true, true, false);
        pane.setEditable(false);
        pane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel main = new JPanel(new BorderLayout());
        main.setBorder(new EmptyBorder(8, 8, 8, 8));
        main.setPreferredSize(new Dimension(900, 700));
        main.add(new JScrollPane(pane), BorderLayout.CENTER);
        addWorkPanel(main);
        addDismissButton();
    }

    /** numbered_source(): the source with line numbers. */
    public static DiaphoraTextDialog numberedSource(String title, String src) {
        DiaphoraTextDialog dlg = new DiaphoraTextDialog(title);
        List<String> lines = Arrays.asList(src.split("\n", -1));
        int width = String.valueOf(lines.size()).length();
        SimpleAttributeSet gray = new SimpleAttributeSet();
        StyleConstants.setForeground(gray, Color.GRAY);
        for (int i = 0; i < lines.size(); i++) {
            dlg.append(String.format("%" + width + "d ", i + 1), gray);
            dlg.append(lines.get(i).replace("\t", "    ") + "\n", null);
        }
        dlg.pane.setCaretPosition(0);
        return dlg;
    }

    /** unified_view(): difflib.unified_diff() of both buffers, +/- lines highlighted. */
    public static DiaphoraTextDialog unifiedDiff(String title, String buf1, String buf2) {
        return unifiedDiff(title, buf1, buf2, null, List.of());
    }

    /**
     * Diaphora-ng: the same with the lines compared through 'key' (null: as
     * they are) and 'notes' above the patch (the Claude diff).
     */
    public static DiaphoraTextDialog unifiedDiff(String title, String buf1, String buf2, UnaryOperator<String> key,
                                                 List<DiaphoraNote> notes) {
        DiaphoraTextDialog dlg = new DiaphoraTextDialog(title);
        for (DiaphoraNote n : notes) {
            dlg.append("// " + n.text() + "\n", n.attributes());
        }
        if (!notes.isEmpty()) {
            dlg.append("\n", null);
        }
        List<String> lines = SideBySideDiff.unifiedDiff(Arrays.asList(buf1.split("\n", -1)),
                                                        Arrays.asList(buf2.split("\n", -1)), key);
        Color bg = dlg.pane.getBackground();
        SimpleAttributeSet macro = new SimpleAttributeSet();
        StyleConstants.setForeground(macro, new Color(0x80, 0x40, 0xc0));
        SimpleAttributeSet added = new SimpleAttributeSet();
        StyleConstants.setBackground(added, DiaphoraColors.diffAdded(bg));
        SimpleAttributeSet removed = new SimpleAttributeSet();
        StyleConstants.setBackground(removed, DiaphoraColors.diffSubtracted(bg));
        // The first two lines are the "---" / "+++" headers
        for (int i = 2; i < lines.size(); i++) {
            String line = lines.get(i).replace("\t", "    ");
            if (line.startsWith("@@")) {
                dlg.append(line, macro);
            } else if (line.startsWith("+")) {
                dlg.append(line, added);
            } else if (line.startsWith("-")) {
                dlg.append(line, removed);
            } else {
                dlg.append(line, null);
            }
            dlg.append("\n", null);
        }
        dlg.pane.setCaretPosition(0);
        return dlg;
    }

    private void append(String text, AttributeSet attrs) {
        StyledDocument doc = pane.getStyledDocument();
        try {
            doc.insertString(doc.getLength(), text, attrs != null ? attrs : SimpleAttributeSet.EMPTY);
        } catch (BadLocationException ignored) {
        }
    }
}
