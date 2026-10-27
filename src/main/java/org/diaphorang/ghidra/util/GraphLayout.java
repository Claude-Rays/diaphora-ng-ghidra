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

import java.util.*;

/**
 * Layered (Sugiyama style) layout of a directed graph, used to draw the graphs
 * that IDA shows with its graph viewer (CDiffGraphViewer, CCallGraphViewer):
 * back edges are reversed, nodes are put in layers by longest path from the
 * roots, long edges get bend points, the order inside each layer is improved
 * with barycenter sweeps and the nodes are centered over their neighbours.
 *
 * Pure geometry, without Swing, so it can be unit tested.
 */
public final class GraphLayout {

    /** Result: top-left corner of every node and the points of every edge. */
    public static final class Result {
        public final double[] x;
        public final double[] y;
        public final int[] layer;
        /** For every input edge: polyline from the source to the target, centers of the box borders. */
        public final List<double[][]> edgePoints;
        public final double width;
        public final double height;

        Result(double[] x, double[] y, int[] layer, List<double[][]> edgePoints, double width, double height) {
            this.x = x;
            this.y = y;
            this.layer = layer;
            this.edgePoints = edgePoints;
            this.width = width;
            this.height = height;
        }
    }

    public static final double H_GAP = 30;
    public static final double V_GAP = 45;

    private GraphLayout() {}

    /**
     * @param widths  width of every node
     * @param heights height of every node
     * @param edges   edges as {source, target}; node 0 is the entry point
     */
    public static Result layout(double[] widths, double[] heights, List<int[]> edges) {
        int n = widths.length;
        if (n == 0) {
            return new Result(new double[0], new double[0], new int[0], new ArrayList<>(), 0, 0);
        }

        List<List<Integer>> succ = new ArrayList<>();
        for (int i = 0; i < n; i++) succ.add(new ArrayList<>());
        for (int[] e : edges) {
            if (e[0] != e[1]) succ.get(e[0]).add(e[1]);
        }

        // 1. Back edges (DFS from the entry point first, then from any unvisited node)
        Set<Long> backEdges = new HashSet<>();
        int[] state = new int[n]; // 0 = new, 1 = on stack, 2 = done
        List<Integer> dfsOrder = new ArrayList<>();
        for (int root = 0; root < n; root++) {
            if (state[root] != 0) continue;
            Deque<int[]> stack = new ArrayDeque<>();
            stack.push(new int[]{root, 0});
            state[root] = 1;
            dfsOrder.add(root);
            while (!stack.isEmpty()) {
                int[] top = stack.peek();
                List<Integer> s = succ.get(top[0]);
                if (top[1] < s.size()) {
                    int next = s.get(top[1]++);
                    if (state[next] == 1) {
                        backEdges.add(key(top[0], next));
                    } else if (state[next] == 0) {
                        state[next] = 1;
                        dfsOrder.add(next);
                        stack.push(new int[]{next, 0});
                    }
                } else {
                    state[top[0]] = 2;
                    stack.pop();
                }
            }
        }

        // 2. Acyclic edges (back edges reversed, self loops and duplicates removed)
        Set<Long> dagSet = new LinkedHashSet<>();
        for (int[] e : edges) {
            if (e[0] == e[1]) continue;
            dagSet.add(backEdges.contains(key(e[0], e[1])) ? key(e[1], e[0]) : key(e[0], e[1]));
        }
        List<int[]> dag = new ArrayList<>();
        for (long k : dagSet) dag.add(new int[]{(int) (k >>> 32), (int) k});

        // 3. Layers: longest path from the sources
        int[] layer = new int[n];
        int[] indeg = new int[n];
        List<List<Integer>> dagSucc = new ArrayList<>();
        for (int i = 0; i < n; i++) dagSucc.add(new ArrayList<>());
        for (int[] e : dag) {
            dagSucc.get(e[0]).add(e[1]);
            indeg[e[1]]++;
        }
        Deque<Integer> queue = new ArrayDeque<>();
        for (int i = 0; i < n; i++) if (indeg[i] == 0) queue.add(i);
        while (!queue.isEmpty()) {
            int v = queue.poll();
            for (int w : dagSucc.get(v)) {
                layer[w] = Math.max(layer[w], layer[v] + 1);
                if (--indeg[w] == 0) queue.add(w);
            }
        }

        // 4. Dummy nodes for edges spanning several layers
        List<Double> w = new ArrayList<>();
        List<Integer> lay = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            w.add(widths[i]);
            lay.add(layer[i]);
        }
        Map<Long, List<Integer>> chains = new HashMap<>(); // dag edge -> nodes from source to target
        List<List<Integer>> up = new ArrayList<>();
        List<List<Integer>> down = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            up.add(new ArrayList<>());
            down.add(new ArrayList<>());
        }
        for (int[] e : dag) {
            List<Integer> chain = new ArrayList<>();
            chain.add(e[0]);
            int prev = e[0];
            for (int l = layer[e[0]] + 1; l < layer[e[1]]; l++) {
                int d = w.size();
                w.add(0.0);
                lay.add(l);
                up.add(new ArrayList<>());
                down.add(new ArrayList<>());
                down.get(prev).add(d);
                up.get(d).add(prev);
                chain.add(d);
                prev = d;
            }
            down.get(prev).add(e[1]);
            up.get(e[1]).add(prev);
            chain.add(e[1]);
            chains.put(key(e[0], e[1]), chain);
        }
        int total = w.size();
        int layers = 0;
        for (int l : lay) layers = Math.max(layers, l + 1);

        // 5. Order inside the layers: DFS order, then barycenter sweeps
        List<List<Integer>> rows = new ArrayList<>();
        for (int l = 0; l < layers; l++) rows.add(new ArrayList<>());
        for (int v : dfsOrder) rows.get(lay.get(v)).add(v);
        for (int v = n; v < total; v++) rows.get(lay.get(v)).add(v);
        double[] pos = new double[total];
        updatePositions(rows, pos);
        for (int sweep = 0; sweep < 8; sweep++) {
            boolean downwards = sweep % 2 == 0;
            for (int i = 0; i < layers; i++) {
                int l = downwards ? i : layers - 1 - i;
                List<List<Integer>> nb = downwards ? up : down;
                List<Integer> row = rows.get(l);
                Map<Integer, Double> bary = new HashMap<>();
                for (int v : row) {
                    List<Integer> adj = nb.get(v);
                    if (adj.isEmpty()) {
                        bary.put(v, pos[v]);
                    } else {
                        double sum = 0;
                        for (int a : adj) sum += pos[a];
                        bary.put(v, sum / adj.size());
                    }
                }
                row.sort(Comparator.comparingDouble(bary::get));
                for (int k = 0; k < row.size(); k++) pos[row.get(k)] = k;
            }
        }

        // 6. Coordinates: rows packed left to right, then centered over the neighbours
        double[] x = new double[total];
        for (List<Integer> row : rows) {
            double cx = 0;
            for (int v : row) {
                x[v] = cx;
                cx += w.get(v) + H_GAP;
            }
        }
        for (int iter = 0; iter < 12; iter++) {
            boolean downwards = iter % 2 == 0;
            for (int i = 0; i < layers; i++) {
                int l = downwards ? i : layers - 1 - i;
                List<Integer> row = rows.get(l);
                List<List<Integer>> nb = downwards ? up : down;
                double[] desired = new double[row.size()];
                for (int k = 0; k < row.size(); k++) {
                    int v = row.get(k);
                    List<Integer> adj = new ArrayList<>(nb.get(v));
                    if (adj.isEmpty()) adj = downwards ? down.get(v) : up.get(v);
                    if (adj.isEmpty()) {
                        desired[k] = x[v];
                    } else {
                        double sum = 0;
                        for (int a : adj) sum += x[a] + w.get(a) / 2;
                        desired[k] = sum / adj.size() - w.get(v) / 2;
                    }
                }
                // Keep the order and the minimum separation
                for (int k = 0; k < row.size(); k++) {
                    int v = row.get(k);
                    x[v] = desired[k];
                    if (k > 0) {
                        int p = row.get(k - 1);
                        x[v] = Math.max(x[v], x[p] + w.get(p) + H_GAP);
                    }
                }
                for (int k = row.size() - 2; k >= 0; k--) {
                    int v = row.get(k);
                    int nx = row.get(k + 1);
                    double limit = x[nx] - w.get(v) - H_GAP;
                    if (x[v] > limit) x[v] = limit;
                }
            }
        }
        double minX = Double.MAX_VALUE;
        double maxX = 0;
        for (int v = 0; v < total; v++) minX = Math.min(minX, x[v]);
        for (int v = 0; v < total; v++) {
            x[v] -= minX;
            maxX = Math.max(maxX, x[v] + w.get(v));
        }

        double[] layerY = new double[layers];
        double[] layerH = new double[layers];
        for (int v = 0; v < n; v++) layerH[layer[v]] = Math.max(layerH[layer[v]], heights[v]);
        double cy = 0;
        for (int l = 0; l < layers; l++) {
            layerY[l] = cy;
            cy += layerH[l] + V_GAP;
        }
        double height = cy - V_GAP;

        double[] rx = Arrays.copyOf(x, n);
        double[] ry = new double[n];
        for (int v = 0; v < n; v++) ry[v] = layerY[layer[v]];

        // 7. Edge polylines, following the chain of dummy nodes
        List<double[][]> points = new ArrayList<>();
        for (int[] e : edges) {
            int s = e[0];
            int t = e[1];
            if (s == t) {
                double bx = rx[s] + widths[s];
                double by = ry[s] + heights[s] / 2;
                points.add(new double[][]{{bx, by - 8}, {bx + 20, by - 8}, {bx + 20, by + 8}, {bx, by + 8}});
                continue;
            }
            boolean reversed = backEdges.contains(key(s, t));
            List<Integer> chain = chains.get(reversed ? key(t, s) : key(s, t));
            List<double[]> pts = new ArrayList<>();
            if (chain == null) {
                pts.add(new double[]{rx[s] + widths[s] / 2, ry[s] + heights[s]});
                pts.add(new double[]{rx[t] + widths[t] / 2, ry[t]});
            } else {
                int first = chain.get(0);
                int last = chain.get(chain.size() - 1);
                pts.add(new double[]{rx[first] + widths[first] / 2, ry[first] + heights[first]});
                for (int k = 1; k < chain.size() - 1; k++) {
                    int d = chain.get(k);
                    double dy = layerY[lay.get(d)];
                    pts.add(new double[]{x[d], dy});
                    pts.add(new double[]{x[d], dy + layerH[lay.get(d)]});
                }
                pts.add(new double[]{rx[last] + widths[last] / 2, ry[last]});
                if (reversed) {
                    // Back edges go up: from the top of the source to the bottom of the target
                    Collections.reverse(pts);
                }
            }
            points.add(pts.toArray(new double[0][]));
        }

        return new Result(rx, ry, layer, points, maxX, Math.max(height, 0));
    }

    private static void updatePositions(List<List<Integer>> rows, double[] pos) {
        for (List<Integer> row : rows) {
            for (int k = 0; k < row.size(); k++) pos[row.get(k)] = k;
        }
    }

    private static long key(int a, int b) {
        return ((long) a << 32) | (b & 0xffffffffL);
    }
}
