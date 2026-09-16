package com.soulbrou.testapp;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * Launcher activity of the test fixture application. On creation it runs the
 * engine methods, logs their results under the SoulbrouE2E tag and renders a
 * summary, so an instrumented suite can assert both the computed values and
 * the visual output after a full protection cycle.
 */
public class MainActivity extends Activity {

    private static final String TAG = "SoulbrouE2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Engine engine = new Engine();

        int add = engine.add(2, 3);
        int fib = engine.fibonacci(12);
        long sum = engine.sumRange(1, 100);
        String text = engine.repeat("soulbrou", 3);
        int[] squares = engine.squares(5);
        int max = engine.maxOf(squares);
        String description = engine.describe(42);
        double average = engine.average(1.5, 2.5, 3.0);
        boolean even = engine.isEven(10);

        Log.i(TAG, "RESULT add=" + add);
        Log.i(TAG, "RESULT fib=" + fib);
        Log.i(TAG, "RESULT sum=" + sum);
        Log.i(TAG, "RESULT text=" + text);
        Log.i(TAG, "RESULT squares=" + squares.length + ":" + squares[0] + "," + squares[1] + "," + squares[2] + "," + squares[3] + "," + squares[4]);
        Log.i(TAG, "RESULT max=" + max);
        Log.i(TAG, "RESULT description=" + description);
        Log.i(TAG, "RESULT average=" + average);
        Log.i(TAG, "RESULT even=" + even);
        Log.i(TAG, "RESULT OK");

        TextView view = new TextView(this);
        view.setTextColor(Color.WHITE);
        view.setTextSize(18f);
        view.setText("add=" + add + " fib=" + fib + " sum=" + sum + " text=" + text
                + " max=" + max + " description=" + description + " average=" + average
                + " even=" + even);
        setContentView(view);
    }
}
