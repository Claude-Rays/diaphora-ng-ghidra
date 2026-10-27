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

/**
 * Result categories for Diaphora matches.
 */
public enum MatchCategory {
    BEST("Best matches"),
    PARTIAL("Partial matches"),
    UNRELIABLE("Unreliable matches"),
    PROBLEMATIC("Problematic matches"),
    UNMATCHED_PRIMARY("Unmatched in Primary"),
    UNMATCHED_SECONDARY("Unmatched in Secondary");

    private final String title;

    MatchCategory(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }
}
