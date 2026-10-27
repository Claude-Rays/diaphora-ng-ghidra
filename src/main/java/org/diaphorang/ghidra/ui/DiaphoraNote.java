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

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import java.awt.Color;

/**
 * Diaphora-ng: a line of the header of a diff view (the "// ..." notes of the
 * Claude diff), with its kind of color.
 */
public record DiaphoraNote(String text, Kind kind) {

    /** Comment, highlighted and error lines. */
    public enum Kind {
        COMMENT, MACRO, ERROR
    }

    public static DiaphoraNote comment(String text) {
        return new DiaphoraNote(text, Kind.COMMENT);
    }

    public static DiaphoraNote macro(String text) {
        return new DiaphoraNote(text, Kind.MACRO);
    }

    public static DiaphoraNote error(String text) {
        return new DiaphoraNote(text, Kind.ERROR);
    }

    /** The text attributes of the note. */
    public SimpleAttributeSet attributes() {
        SimpleAttributeSet a = new SimpleAttributeSet();
        switch (kind) {
            case MACRO -> StyleConstants.setForeground(a, new Color(0x80, 0x40, 0xc0));
            case ERROR -> StyleConstants.setForeground(a, new Color(0xd0, 0x30, 0x30));
            default -> StyleConstants.setForeground(a, new Color(0x4a, 0x8a, 0x4a));
        }
        return a;
    }
}
