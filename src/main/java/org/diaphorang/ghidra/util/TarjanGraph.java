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
 *
 * The Tarjan and topological sort code is a port of others/tarjan_sort.py:
 *   Tarjan's algorithm and topological sorting implementation in Python
 *   by Paul Harrison (http://www.logarithmic.net/pfh-files/blog/01208083168/)
 */
package org.diaphorang.ghidra.util;

import java.util.*;

/**
 * Tarjan's algorithm for strongly connected components and robust topological sorting.
 */
public class TarjanGraph {

    private final Map<Long, List<Long>> adj = new LinkedHashMap<>();
    private int index = 0;
    private final Map<Long, Integer> indices = new HashMap<>();
    private final Map<Long, Integer> lowlinks = new HashMap<>();
    private final Deque<Long> stack = new ArrayDeque<>();
    private final Set<Long> onStack = new HashSet<>();
    private final List<List<Long>> sccResult = new ArrayList<>();

    public void addNode(long u) {
        adj.putIfAbsent(u, new ArrayList<>());
    }

    public void addEdge(long u, long v) {
        addNode(u);
        addNode(v);
        adj.get(u).add(v);
    }

    public List<List<Long>> getStronglyConnectedComponents() {
        indices.clear();
        lowlinks.clear();
        stack.clear();
        onStack.clear();
        sccResult.clear();
        index = 0;

        for (Long node : adj.keySet()) {
            if (!indices.containsKey(node)) {
                strongConnect(node);
            }
        }
        return sccResult;
    }

    /**
     * Iterative version of Tarjan's strongconnect (big functions with thousands of
     * basic blocks would overflow the Java stack with the recursive version).
     */
    private void strongConnect(long root) {
        Deque<long[]> work = new ArrayDeque<>(); // {node, next neighbour index}
        visit(root);
        work.push(new long[]{root, 0});

        while (!work.isEmpty()) {
            long[] frame = work.peek();
            long v = frame[0];
            List<Long> neighbors = adj.getOrDefault(v, Collections.emptyList());

            if (frame[1] < neighbors.size()) {
                long w = neighbors.get((int) frame[1]++);
                if (!indices.containsKey(w)) {
                    visit(w);
                    work.push(new long[]{w, 0});
                } else if (onStack.contains(w)) {
                    lowlinks.put(v, Math.min(lowlinks.get(v), indices.get(w)));
                }
                continue;
            }

            work.pop();
            if (lowlinks.get(v).equals(indices.get(v))) {
                List<Long> component = new ArrayList<>();
                long w;
                do {
                    w = stack.pop();
                    onStack.remove(w);
                    component.add(w);
                } while (w != v);
                sccResult.add(component);
            }
            if (!work.isEmpty()) {
                long parent = work.peek()[0];
                lowlinks.put(parent, Math.min(lowlinks.get(parent), lowlinks.get(v)));
            }
        }
    }

    private void visit(long v) {
        indices.put(v, index);
        lowlinks.put(v, index);
        index++;
        stack.push(v);
        onStack.add(v);
    }

    public int countLoops() {
        List<List<Long>> scc = getStronglyConnectedComponents();
        int loops = 0;
        for (List<Long> comp : scc) {
            if (comp.size() > 1) {
                loops++;
            } else if (comp.size() == 1) {
                long singleNode = comp.get(0);
                List<Long> succs = adj.get(singleNode);
                if (succs != null && succs.contains(singleNode)) {
                    loops++;
                }
            }
        }
        return loops;
    }

    public List<List<Long>> getRobustTopologicalSort() {
        List<List<Long>> scc = getStronglyConnectedComponents();
        // Return components in topological order (reverse of discovery)
        Collections.reverse(scc);
        return scc;
    }
}
