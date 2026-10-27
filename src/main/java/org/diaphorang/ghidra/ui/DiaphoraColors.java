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

import generic.theme.Gui;
import org.diaphorang.ghidra.model.MatchCategory;
import org.diaphorang.ghidra.model.MatchItem;

import java.awt.Color;

/**
 * Colors used by Diaphora (diaphora_config.py / diaphora-idafree config.hpp).
 *
 * The original values are IDA bgcolor_t values (0xBBGGRR). They are designed for
 * a white background, so with a dark Ghidra theme they are mixed with the
 * background to keep the theme's text readable, like diaphora-idafree does.
 */
public final class DiaphoraColors {

    // HIGHLIGHT_FUNCTION_* (used by "Highlight matches")
    private static final int HIGHLIGHT_FUNCTION_BEST = 0xffff99;
    private static final int HIGHLIGHT_FUNCTION_PARTIAL = 0x99ff99;
    private static final int HIGHLIGHT_FUNCTION_UNRELIABLE = 0x9999ff;

    // GRAPH_BBLOCK_MATCH_* (graph diff); PERFECT is white, i.e. no color
    private static final int GRAPH_BBLOCK_MATCH_PARTIAL = 0xCCFFFF;
    private static final int GRAPH_BBLOCK_MATCH_NONE = 0xCCCCFF;

    // CALLGRAPH_COLOR_TARGET (callers and callees are 0xFFFFFF)
    private static final int CALLGRAPH_COLOR_TARGET = 0xEEFF00;

    // LITTLE_ORANGE, rows that seem false positives
    private static final int LITTLE_ORANGE = 0x026AFD;

    /** Strength of the row colors over the table background (diaphora-idafree ROW_COLOR_STRENGTH). */
    private static final double ROW_COLOR_STRENGTH = 0.55;
    /** Strength of the highlight colors over a dark background. */
    private static final double DARK_STRENGTH = 0.40;
    private static final Color DARK_BASE = new Color(0x20, 0x20, 0x20);

    private DiaphoraColors() {}

    /** IDA bgcolor_t (0xBBGGRR) to a Java color. */
    static Color fromBgr(int bgr) {
        return new Color(bgr & 0xFF, (bgr >> 8) & 0xFF, (bgr >> 16) & 0xFF);
    }

    /** Mix @c over @base: strength 1.0 is @c, 0.0 is @base. */
    static Color mix(Color c, Color base, double strength) {
        int r = (int) Math.round(base.getRed() + (c.getRed() - base.getRed()) * strength);
        int g = (int) Math.round(base.getGreen() + (c.getGreen() - base.getGreen()) * strength);
        int b = (int) Math.round(base.getBlue() + (c.getBlue() - base.getBlue()) * strength);
        return new Color(clamp(r), clamp(g), clamp(b));
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }

    private static boolean isDark() {
        try {
            return Gui.isDarkTheme();
        } catch (Throwable t) {
            return false;
        }
    }

    /** A light color designed for white backgrounds, adapted to the current theme. */
    private static Color themed(Color c) {
        return isDark() ? mix(c, DARK_BASE, DARK_STRENGTH) : c;
    }

    public static Color highlightColor(MatchCategory category) {
        switch (category) {
            case BEST:
                return themed(fromBgr(HIGHLIGHT_FUNCTION_BEST));
            case PARTIAL:
                return themed(fromBgr(HIGHLIGHT_FUNCTION_PARTIAL));
            case UNRELIABLE:
                return themed(fromBgr(HIGHLIGHT_FUNCTION_UNRELIABLE));
            default:
                return null;
        }
    }

    /** CALLGRAPH_COLOR_TARGET; callers and callees are white, i.e. no color. */
    public static Color callgraphTargetColor() {
        return themed(fromBgr(CALLGRAPH_COLOR_TARGET));
    }

    public static Color blockPartialColor() {
        return themed(fromBgr(GRAPH_BBLOCK_MATCH_PARTIAL));
    }

    public static Color blockNoneColor() {
        return themed(fromBgr(GRAPH_BBLOCK_MATCH_NONE));
    }

    // diaphora-idafree ui.cpp: SEG_ADDED / SEG_CHANGED / SEG_SUBTRACTED, the original
    // DIFF_COLOR_* made translucent (alpha 0x30, 0x48 with dark themes) over the
    // background of the viewer, so they are pale and keep the text readable.
    private static final Color SEG_ADDED = fromBgr(0x00B000);
    private static final Color SEG_CHANGED = fromBgr(0x00C8E0);
    private static final Color SEG_SUBTRACTED = fromBgr(0x0000E0);

    private static Color segColor(Color c, Color background) {
        Color base = background != null ? background : (isDark() ? DARK_BASE : Color.WHITE);
        double alpha = (isDark() ? 0x48 : 0x30) / 255.0;
        return mix(c, base, alpha);
    }

    public static Color diffAdded(Color background) {
        return segColor(SEG_ADDED, background);
    }

    public static Color diffChanged(Color background) {
        return segColor(SEG_CHANGED, background);
    }

    public static Color diffSubtracted(Color background) {
        return segColor(SEG_SUBTRACTED, background);
    }

    /**
     * Row color of a match, as OnGetLineAttr() in diaphora_ida.py: from green
     * (ratio 1.0) to purple (ratio 0.0), orange for likely false positives.
     * Softened over the table background like diaphora-idafree.
     */
    public static Color rowColor(MatchItem item, Color background) {
        Color c;
        if (seemsFalsePositive(item.getName1(), item.getName2())) {
            c = fromBgr(LITTLE_ORANGE);
        } else {
            double ratio = Math.max(0.0, Math.min(1.0, item.getRatio()));
            int red = (int) Math.abs(164 * (1 - ratio));
            int green = (int) Math.abs(128 * ratio);
            int blue = (int) Math.abs(255 * (1 - ratio));
            c = new Color(red, green, blue);
        }
        Color base = background != null ? background : (isDark() ? DARK_BASE : Color.WHITE);
        return mix(c, base, ROW_COLOR_STRENGTH);
    }

    /**
     * seems_false_positive(): both functions have meaningful names and neither
     * name contains the other.
     */
    static boolean seemsFalsePositive(String name1, String name2) {
        if (name1 == null || name2 == null) return false;
        name1 = stripChars(name1);
        name2 = stripChars(name2);
        if (name1.startsWith("sub_") || name2.startsWith("sub_")) return false;
        if (name1.equals(name2)) return false;
        return !name1.contains(name2) && !name2.contains(name1);
    }

    private static String stripChars(String name) {
        int end = name.length();
        while (end > 0 && (name.charAt(end - 1) == '_' || name.charAt(end - 1) == '0')) end--;
        name = name.substring(0, end);
        int start = 0;
        end = name.length();
        while (start < end && name.charAt(start) == '.') start++;
        while (end > start && name.charAt(end - 1) == '.') end--;
        return name.substring(start, end);
    }
}
