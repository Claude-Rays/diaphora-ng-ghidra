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
package org.diaphorang.ghidra.util;

import java.util.List;
import java.util.Map;

/**
 * Calculation of Diaphora's MD-Index for control flow graphs.
 */
public final class MDIndex {

    private static final double RT2 = Math.sqrt(2.0);
    private static final double RT3 = Math.sqrt(3.0);
    private static final double RT5 = Math.sqrt(5.0);
    private static final double RT7 = Math.sqrt(7.0);

    private MDIndex() {}

    public static double calculate(List<long[]> edges, Map<Long, Integer> topoOrder, Map<Long, int[]> degrees) {
        if (edges == null || edges.isEmpty() || topoOrder == null) {
            return 0.0;
        }

        double mdIndex = 0.0;
        for (long[] edge : edges) {
            long src = edge[0];
            long dst = edge[1];

            Integer order = topoOrder.get(src);
            double z0 = (order != null) ? order : 0.0;

            int[] degSrc = degrees.getOrDefault(src, new int[]{0, 0});
            int[] degDst = degrees.getOrDefault(dst, new int[]{0, 0});

            // Same formula as diaphora_ida.py: md_index = sum(1 / sqrt(emb))
            double emb = z0 + degSrc[0] * RT2 + degSrc[1] * RT3 + degDst[0] * RT5 + degDst[1] * RT7;
            if (emb > 0) {
                mdIndex += 1.0 / Math.sqrt(emb);
            }
        }
        return mdIndex;
    }
}
