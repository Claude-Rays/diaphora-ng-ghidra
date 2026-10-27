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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

/**
 * Prime generation and Small Prime Product (SPP) utilities.
 */
public final class PrimeUtils {

    private static final int MAX_PRIMES = 500000;
    private static int[] primes;

    static {
        initPrimes(MAX_PRIMES);
    }

    private PrimeUtils() {}

    private static synchronized void initPrimes(int limit) {
        BitSet sieve = new BitSet(limit);
        sieve.set(2, limit);
        for (int p = 2; p * p < limit; p = sieve.nextSetBit(p + 1)) {
            for (int multiple = p * p; multiple < limit; multiple += p) {
                sieve.clear(multiple);
            }
        }

        List<Integer> list = new ArrayList<>();
        for (int p = sieve.nextSetBit(0); p >= 0; p = sieve.nextSetBit(p + 1)) {
            list.add(p);
        }
        primes = new int[list.size()];
        for (int i = 0; i < list.size(); i++) {
            primes[i] = list.get(i);
        }
    }

    public static int getPrime(int index) {
        if (index < 0) return 2;
        if (index >= primes.length) {
            return primes[primes.length - 1];
        }
        return primes[index];
    }

    public static BigInteger calculateMnemonicSPP(List<String> mnemonics) {
        if (mnemonics == null || mnemonics.isEmpty()) {
            return BigInteger.ONE;
        }

        BigInteger product = BigInteger.ONE;
        for (String mnem : mnemonics) {
            if (mnem == null || mnem.isEmpty()) continue;
            int hash = Math.abs(mnem.toLowerCase().hashCode()) % 1000;
            int prime = getPrime(hash);
            product = product.multiply(BigInteger.valueOf(prime));
        }
        return product;
    }

    /**
     * Structural tokens of C pseudo-code. Their order defines the prime assigned to
     * each one. Identifiers and literals are intentionally ignored, so the product
     * approximates Diaphora's Hex-Rays AST primes hash (product of one prime per
     * ctree item type) and survives variable renames and address changes.
     */
    private static final String[] AST_TOKENS = {
        "if", "else", "while", "for", "do", "switch", "case", "default", "return",
        "goto", "break", "continue", "sizeof", "CALL",
        "<<=", ">>=", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        "+", "-", "*", "/", "%", "<", ">", "=", "!", "~", "&", "|", "^", "?", "[", "."
    };
    private static final java.util.Map<String, Integer> AST_TOKEN_INDEX = new java.util.HashMap<>();
    private static final java.util.regex.Pattern AST_TOKEN_PATTERN;

    static {
        StringBuilder ops = new StringBuilder();
        for (int i = 0; i < AST_TOKENS.length; i++) {
            AST_TOKEN_INDEX.put(AST_TOKENS[i], i);
            if (!Character.isLetter(AST_TOKENS[i].charAt(0))) {
                if (ops.length() > 0) ops.append('|');
                ops.append(java.util.regex.Pattern.quote(AST_TOKENS[i]));
            }
        }
        // Identifiers (optionally followed by '(' which means a call) or operators
        AST_TOKEN_PATTERN = java.util.regex.Pattern.compile(
            "([A-Za-z_][A-Za-z0-9_]*)(\\s*\\()?|(" + ops + ")");
    }

    public static BigInteger calculatePseudocodeSPP(String pseudocode) {
        if (pseudocode == null || pseudocode.isEmpty()) {
            return BigInteger.ONE;
        }

        BigInteger product = BigInteger.ONE;
        java.util.regex.Matcher m = AST_TOKEN_PATTERN.matcher(pseudocode);
        while (m.find()) {
            Integer idx;
            if (m.group(1) != null) {
                idx = AST_TOKEN_INDEX.get(m.group(1));
                if (idx == null) {
                    if (m.group(2) == null) continue;
                    idx = AST_TOKEN_INDEX.get("CALL");
                }
            } else {
                idx = AST_TOKEN_INDEX.get(m.group(3));
            }
            if (idx == null) continue;
            // Skip prime 2 so the product never ends up as a plain power of two
            product = product.multiply(BigInteger.valueOf(getPrime(idx + 1)));
        }
        return product;
    }
}
