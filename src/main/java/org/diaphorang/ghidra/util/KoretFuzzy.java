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
 * The fuzzy hash is a port of jkutils/kfuzzy.py:
 *   Fuzzy hashing algorithms
 *   Copyright (C) 2009-2023, Joxean Koret
 *   Licensed under the GNU Lesser General Public License, version 2.1 or later.
 */
package org.diaphorang.ghidra.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Port of CKoretFuzzyHashing.
 * Generates triple fuzzy hash: "hash1;hash2;hash3".
 */
public final class KoretFuzzy {

    private static final int OUTPUT_SIZE = 32;

    private KoretFuzzy() {}

    public static String hashBytes(byte[] bytes, int bsize) {
        if (bytes == null || bytes.length == 0) {
            return ";;";
        }
        byte[] mix = mixBlocks(bytes, bsize);
        byte[] rev = reverse(bytes);

        String h1 = hash(mix, bsize);
        String h2 = hash(bytes, bsize);
        String h3 = hash(rev, bsize);
        return h1 + ";" + h2 + ";" + h3;
    }

    public static String hashString(String s, int bsize) {
        if (s == null || s.isEmpty()) {
            return ";;";
        }
        return hashBytes(s.getBytes(StandardCharsets.UTF_8), bsize);
    }

    private static String hash(byte[] bytes, int bsize) {
        List<Integer> ret = new ArrayList<>();
        int totalSize = bytes.length;
        int idx = 0;
        while (true) {
            int chunkSize = idx * bsize;
            long sum = 0;
            for (int k = chunkSize; k < chunkSize + bsize && k < totalSize; k++) {
                sum += (bytes[k] & 0xFF);
            }
            int c = (int) (sum % 255);
            if (c != 255 && c != 0) {
                ret.add(c);
            }
            idx++;
            if (chunkSize + bsize > totalSize) {
                break;
            }
        }

        int size = Math.min(ret.size() / OUTPUT_SIZE, 1);
        List<Byte> buf = new ArrayList<>();
        for (int c = 0; c < OUTPUT_SIZE; c++) {
            int slEnd = Math.min(ret.size(), c + size + 1);
            int slLen = slEnd > c ? slEnd - c : 0;
            if (slLen >= 2) {
                // The original builds a str of chr(value) and calls encode(), so values
                // >= 0x80 are emitted as 2-byte UTF-8 sequences.
                int val = ret.get(c + 1);
                for (int rep = 0; rep < 2; rep++) {
                    if (val < 0x80) {
                        buf.add((byte) val);
                    } else {
                        buf.add((byte) (0xC0 | (val >> 6)));
                        buf.add((byte) (0x80 | (val & 0x3F)));
                    }
                }
            }
        }

        byte[] raw = new byte[buf.size()];
        for (int i = 0; i < buf.size(); i++) {
            raw[i] = buf.get(i);
        }

        String b64 = Base64.getEncoder().encodeToString(raw);
        while (b64.endsWith("=")) {
            b64 = b64.substring(0, b64.length() - 1);
        }
        if (b64.length() > OUTPUT_SIZE) {
            b64 = b64.substring(0, OUTPUT_SIZE);
        }
        return b64;
    }

    private static byte[] mixBlocks(byte[] bytes, int bsize) {
        List<Byte> result = new ArrayList<>();
        int idx = 0;
        while (true) {
            int s1 = idx * bsize;
            int len = Math.min(bsize, Math.max(0, bytes.length - s1));
            if (len > 0) {
                for (int rep = 0; rep < 2; rep++) {
                    for (int k = 0; k < len; k++) {
                        result.add(bytes[s1 + k]);
                    }
                }
            }
            idx++;
            if (len < bsize) {
                break;
            }
        }
        byte[] arr = new byte[result.size()];
        for (int i = 0; i < result.size(); i++) {
            arr[i] = result.get(i);
        }
        return arr;
    }

    private static byte[] reverse(byte[] bytes) {
        byte[] rev = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            rev[i] = bytes[bytes.length - 1 - i];
        }
        return rev;
    }
}
