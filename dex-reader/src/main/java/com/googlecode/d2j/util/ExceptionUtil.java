package com.googlecode.d2j.util;

import com.googlecode.d2j.DexException;

public class ExceptionUtil {

    public static void printStackTraceEx(Throwable t, int deep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < deep + 1; i++) {
            sb.append(".");
        }
        sb.append(' ');
        if (t instanceof DexException) {
            sb.append(t.getMessage());
            System.err.println(sb.toString());
            if (t.getCause() != null) {
                printStackTraceEx(t.getCause(), deep + 1);
            }
        } else {
            if (t != null) {
                System.err.println(sb.append("ROOT cause:").toString());
                t.printStackTrace(System.err);
            }
        }
    }

}
