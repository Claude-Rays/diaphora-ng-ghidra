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
package org.diaphorang.ghidra.model;

import java.util.List;

/**
 * Representation of a Diaphora SQL heuristic.
 */
public class Heuristic {

    public static final int HEUR_TYPE_NO_FPS = 0;
    public static final int HEUR_TYPE_RATIO = 1;
    public static final int HEUR_TYPE_RATIO_MAX = 2;
    public static final int HEUR_TYPE_RATIO_MAX_TRUSTED = 3;

    public static final int HEUR_FLAG_NONE = 0;
    public static final int HEUR_FLAG_UNRELIABLE = 1;
    public static final int HEUR_FLAG_SLOW = 2;
    public static final int HEUR_FLAG_SAME_CPU = 3;

    private String name;
    private String category;
    private int ratio;
    private double min;
    private List<Integer> flags;
    private String sql;

    public Heuristic() {}

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public int getRatio() {
        return ratio;
    }

    public void setRatio(int ratio) {
        this.ratio = ratio;
    }

    public double getMin() {
        return min;
    }

    public void setMin(double min) {
        this.min = min;
    }

    public List<Integer> getFlags() {
        return flags;
    }

    public void setFlags(List<Integer> flags) {
        this.flags = flags;
    }

    public String getSql() {
        return sql;
    }

    public void setSql(String sql) {
        this.sql = sql;
    }

    public boolean hasFlag(int flag) {
        return flags != null && flags.contains(flag);
    }
}
