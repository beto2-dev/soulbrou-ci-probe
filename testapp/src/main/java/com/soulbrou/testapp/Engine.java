package com.soulbrou.testapp;

import android.util.Log;

/**
 * Computational methods used as conversion targets by the end to end test suite.
 * Every method in this class is intentionally small, deterministic and free of
 * framework dependencies so its semantics can be verified after a full
 * protection cycle.
 */
public final class Engine {

    private static final String TAG = "SoulbrouE2E";

    public int add(int a, int b) {
        return a + b;
    }

    public int multiply(int a, int b) {
        return a * b;
    }

    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        int a = 0;
        int b = 1;
        for (int i = 2; i <= n; i++) {
            int next = a + b;
            a = b;
            b = next;
        }
        return b;
    }

    public long sumRange(int from, int to) {
        long total = 0;
        for (int i = from; i <= to; i++) {
            total += i;
        }
        return total;
    }

    public String repeat(String text, int times) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < times; i++) {
            builder.append(text);
        }
        return builder.toString();
    }

    public int[] squares(int count) {
        int[] result = new int[count];
        for (int i = 0; i < count; i++) {
            result[i] = i * i;
        }
        return result;
    }

    public boolean isEven(int value) {
        return (value & 1) == 0;
    }

    public double average(double a, double b, double c) {
        return (a + b + c) / 3.0;
    }

    public int maxOf(int[] values) {
        int max = values[0];
        for (int v : values) {
            if (v > max) {
                max = v;
            }
        }
        return max;
    }

    public String describe(int value) {
        if (value < 0) {
            return "negative";
        } else if (isEven(value)) {
            return "even:" + value;
        } else {
            return "odd:" + value;
        }
    }
}
