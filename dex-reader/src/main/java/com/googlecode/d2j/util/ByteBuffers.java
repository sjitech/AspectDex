package com.googlecode.d2j.util;

import com.googlecode.d2j.DexLabel;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;

public class ByteBuffers {
    public static ByteBuffer slice(ByteBuffer in, int offset, int length) {
        in.position(offset);
        ByteBuffer b = in.slice();
        b.limit(length);
        b.order(ByteOrder.LITTLE_ENDIAN);
        return b;
    }

    public static void skip(ByteBuffer in, int bytes) {
        in.position(in.position() + bytes);
    }

    public static long readIntBits(ByteBuffer in, int before) {
        int length = ((before >> 5) & 0x7) + 1;
        long value = 0;
        for (int j = 0; j < length; j++) {
            value |= ((long) (0xFF & in.get())) << (j * 8);
        }
        int shift = (8 - length) * 8;
        return value << shift >> shift;
    }

    public static long readUIntBits(ByteBuffer in, int before) {
        int length = ((before >> 5) & 0x7) + 1;
        long value = 0;
        for (int j = 0; j < length; j++) {
            value |= ((long) (0xFF & in.get())) << (j * 8);
        }
        return value;
    }

    public static long readFloatBits(ByteBuffer in, int before) {
        int bytes = ((before >> 5) & 0x7) + 1;
        long result = 0L;
        for (int i = 0; i < bytes; ++i) {
            result |= ((long) (0xFF & in.get())) << (i * 8);
        }
        result <<= (8 - bytes) * 8;
        return result;
    }

    public static int sshort(byte[] data, int offset) {
        return (data[offset + 1] << 8) | (0xFF & data[offset]);
    }

    public static int ushort(byte[] data, int offset) {
        return ((0xFF & data[offset + 1]) << 8) | (0xFF & data[offset]);
    }

    public static int sint(byte[] data, int offset) {
        return (data[offset + 3] << 24) | ((0xFF & data[offset + 2]) << 16) | ((0xFF & data[offset + 1]) << 8)
                | ((0xFF & data[offset]));
    }

    public static int uint(byte[] data, int offset) {
        return sint(data, offset);
    }

    public static int ubyte(byte[] insns, int offset) {
        return 0xFF & insns[offset];
    }

    public static int sbyte(byte[] insns, int offset) {
        return insns[offset];
    }

    public static int readULeb128i(ByteBuffer in) {
        int value = 0;
        int count = 0;
        int b = in.get();
        while ((b & 0x80) != 0) {
            value |= (b & 0x7f) << count;
            count += 7;
            b = in.get();
        }
        value |= (b & 0x7f) << count;
        return value;
    }

    public static int readLeb128i(ByteBuffer in) {
        int bitpos = 0;
        int vln = 0;
        do {
            int inp = in.get();
            vln |= (inp & 0x7F) << bitpos;
            bitpos += 7;
            if ((inp & 0x80) == 0) {
                break;
            }
        } while (true);
        if (((1L << (bitpos - 1)) & vln) != 0) {
            vln -= (1L << bitpos);
        }
        return vln;
    }

    public static void order(Map<Integer, DexLabel> labelsMap, int offset) {
        if (!labelsMap.containsKey(offset)) {
            labelsMap.put(offset, new DexLabel(offset));
        }
    }
}
