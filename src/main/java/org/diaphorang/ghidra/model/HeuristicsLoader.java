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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads heuristics definitions from JSON resource.
 */
public final class HeuristicsLoader {

    private static List<Heuristic> cachedHeuristics = null;

    private HeuristicsLoader() {}

    public static synchronized List<Heuristic> getHeuristics() {
        if (cachedHeuristics != null) {
            return cachedHeuristics;
        }

        try (InputStream in = HeuristicsLoader.class.getResourceAsStream("/diaphorang/heuristics.json")) {
            if (in == null) {
                System.err.println("Could not locate /diaphorang/heuristics.json on classpath!");
                return new ArrayList<>();
            }
            try (InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                Type listType = new TypeToken<List<Heuristic>>() {}.getType();
                cachedHeuristics = new Gson().fromJson(reader, listType);
                return cachedHeuristics;
            }
        } catch (Exception e) {
            System.err.println("Error loading heuristics: " + e.getMessage());
            return new ArrayList<>();
        }
    }
}
