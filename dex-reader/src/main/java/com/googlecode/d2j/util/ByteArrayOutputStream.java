package com.googlecode.d2j.util;

import java.io.IOException;
import java.io.InputStream;

public class ByteArrayOutputStream extends java.io.ByteArrayOutputStream {
    public byte[] getBuf() {
        return buf;
    }
}
