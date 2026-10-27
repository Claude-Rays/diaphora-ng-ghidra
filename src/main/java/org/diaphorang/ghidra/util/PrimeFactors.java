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
import java.util.*;

/**
 * Port of the parts of jkutils/factor.py used by Diaphora: factorization() and
 * difference_ratio(), used by ast_ratio() when comparing the AST primes hashes.
 */
public final class PrimeFactors {

    private static final int[] SMALL_PRIMES;
    private static final Map<BigInteger, Map<BigInteger, Integer>> FACTORS_CACHE = new HashMap<>();

    static {
        // primesbelow(10000)
        boolean[] composite = new boolean[10000];
        List<Integer> l = new ArrayList<>();
        for (int i = 2; i < 10000; i++) {
            if (composite[i]) continue;
            l.add(i);
            for (int j = i * i; j < 10000; j += i) composite[j] = true;
        }
        SMALL_PRIMES = l.stream().mapToInt(Integer::intValue).toArray();
    }

    private PrimeFactors() {}

    /** pollard_brent(n): a (not necessarily prime) factor of n. */
    private static BigInteger pollardBrent(BigInteger n) {
        if (!n.testBit(0)) return BigInteger.TWO;
        if (n.mod(BigInteger.valueOf(3)).signum() == 0) return BigInteger.valueOf(3);
        Random rnd = new Random(n.longValue());
        BigInteger nm1 = n.subtract(BigInteger.ONE);
        while (true) {
            BigInteger y = new BigInteger(n.bitLength(), rnd).mod(nm1).add(BigInteger.ONE);
            BigInteger c = new BigInteger(n.bitLength(), rnd).mod(nm1).add(BigInteger.ONE);
            BigInteger m = new BigInteger(n.bitLength(), rnd).mod(nm1).add(BigInteger.ONE);
            BigInteger g = BigInteger.ONE, r = BigInteger.ONE, q = BigInteger.ONE;
            BigInteger x = y, ys = y;
            while (g.equals(BigInteger.ONE)) {
                x = y;
                for (BigInteger i = BigInteger.ZERO; i.compareTo(r) < 0; i = i.add(BigInteger.ONE)) {
                    y = y.multiply(y).add(c).mod(n);
                }
                BigInteger k = BigInteger.ZERO;
                while (k.compareTo(r) < 0 && g.equals(BigInteger.ONE)) {
                    ys = y;
                    BigInteger lim = m.min(r.subtract(k));
                    for (BigInteger i = BigInteger.ZERO; i.compareTo(lim) < 0; i = i.add(BigInteger.ONE)) {
                        y = y.multiply(y).add(c).mod(n);
                        q = q.multiply(x.subtract(y).abs()).mod(n);
                    }
                    g = q.gcd(n);
                    k = k.add(m);
                }
                r = r.shiftLeft(1);
            }
            if (g.equals(n)) {
                while (true) {
                    ys = ys.multiply(ys).add(c).mod(n);
                    g = x.subtract(ys).abs().gcd(n);
                    if (g.compareTo(BigInteger.ONE) > 0) break;
                }
            }
            if (!g.equals(n)) return g;
        }
    }

    private static void primeFactors(BigInteger n, List<BigInteger> factors) {
        for (int p : SMALL_PRIMES) {
            BigInteger checker = BigInteger.valueOf(p);
            if (checker.multiply(checker).compareTo(n) > 0) break;
            while (n.mod(checker).signum() == 0) {
                factors.add(checker);
                n = n.divide(checker);
            }
        }
        while (n.compareTo(BigInteger.ONE) > 0) {
            if (n.isProbablePrime(40)) {
                factors.add(n);
                break;
            }
            BigInteger factor = pollardBrent(n);
            primeFactors(factor, factors);
            n = n.divide(factor);
        }
    }

    /** factorization(n): prime -> exponent. */
    public static synchronized Map<BigInteger, Integer> factorization(BigInteger n) {
        Map<BigInteger, Integer> cached = FACTORS_CACHE.get(n);
        if (cached != null) return cached;
        Map<BigInteger, Integer> factors = new LinkedHashMap<>();
        List<BigInteger> l = new ArrayList<>();
        if (n.compareTo(BigInteger.ONE) > 0) primeFactors(n, l);
        for (BigInteger p : l) factors.merge(p, 1, Integer::sum);
        FACTORS_CACHE.put(n, factors);
        return factors;
    }

    /** difference_ratio(num1, num2) */
    public static double differenceRatio(BigInteger num1, BigInteger num2) {
        Map<BigInteger, Integer> s0 = factorization(num1);
        Map<BigInteger, Integer> s1 = factorization(num2);
        Map<BigInteger, Integer> diffs = new HashMap<>();
        for (Map.Entry<BigInteger, Integer> e : s0.entrySet()) {
            Integer other = s1.get(e.getKey());
            if (other != null) {
                if (!other.equals(e.getValue())) diffs.put(e.getKey(), Math.abs(e.getValue() - other));
            } else {
                diffs.put(e.getKey(), e.getValue());
            }
        }
        for (Map.Entry<BigInteger, Integer> e : s1.entrySet()) {
            Integer other = s0.get(e.getKey());
            if (other != null) {
                if (!other.equals(e.getValue())) diffs.put(e.getKey(), Math.abs(e.getValue() - other));
            } else {
                diffs.put(e.getKey(), e.getValue());
            }
        }
        int total = Math.max(sum(s0), sum(s1));
        if (total == 0) return 0; // ZeroDivisionError in the original
        return 1 - (sum(diffs) * 1.0 / total);
    }

    private static int sum(Map<BigInteger, Integer> m) {
        int s = 0;
        for (int v : m.values()) s += v;
        return s;
    }
}
