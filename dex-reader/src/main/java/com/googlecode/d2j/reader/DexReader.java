package com.googlecode.d2j.reader;

import com.googlecode.d2j.*;
import com.googlecode.d2j.node.DexAnnotationNode;
import com.googlecode.d2j.util.ByteBuffers;
import com.googlecode.d2j.util.ByteStreams;
import com.googlecode.d2j.util.ExceptionUtil;
import com.googlecode.d2j.util.Mutf8;
import com.googlecode.d2j.util.zip.ZipEntry;
import com.googlecode.d2j.util.zip.ZipFile;
import com.googlecode.d2j.visitors.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UTFDataFormatException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class DexReader {
    final private List<SingleDexReader> readers = new ArrayList<>();

    public DexReader(ByteBuffer in) throws IOException {
        in.position(0);
        in = in.asReadOnlyBuffer();

        if (in.remaining() < 3) {
            throw new IOException("File too small to be a dex/zip");
        }
        if ("dex".equals(in.asCharBuffer().limit(3).toString())) {// dex
            readers.add(new SingleDexReader(in));
        } else if ("PK".equals(in.asCharBuffer().limit(2).toString())) {// ZIP
            try (ZipFile zipFile = new ZipFile(in)) {
                for (ZipEntry e : zipFile.entries()) {
                    String entryName = e.getName();
                    if (entryName.endsWith(".dex")) {
                        readers.add(new SingleDexReader(ByteBuffer.wrap(ByteStreams.toByteArray(zipFile.getInputStream(e)))));
                    }
                }
            }
            if (readers.size() == 0) {
                throw new IOException("Can not find classes.dex in zip file");
            }
        } else {
            throw new IOException("the src file not a .dex or zip file");
        }
    }

    public DexReader(byte[] data) throws IOException {
        this(ByteBuffer.wrap(data));
    }

    public DexReader(File file) throws IOException {
        this(file.toPath());
    }

    public DexReader(Path file) throws IOException {
        this(Files.readAllBytes(file));
    }

    public DexReader(String file) throws IOException {
        this(new File(file));
    }

    public DexReader(InputStream is) throws IOException {
        this(ByteStreams.toByteArray(is));
    }

    public void pipe(DexFileVisitor dv) {
        pipe(dv, 0);
    }

    public void pipe(DexFileVisitor dv, int config) {
        readers.forEach(reader -> reader.pipe(dv, config));
    }

    /**
     * skip debug infos in dex file.
     */
    public static final int SKIP_DEBUG = 1;
    /**
     * skip code info in dex file, this indicate {@link #SKIP_DEBUG}
     */
    public static final int SKIP_CODE = 1 << 2;
    /**
     * skip annotation info in dex file.
     */
    public static final int SKIP_ANNOTATION = 1 << 3;
    /**
     * skip field constant in dex file.
     */
    public static final int SKIP_FIELD_CONSTANT = 1 << 4;
    /**
     * ignore read exception
     */
    public static final int IGNORE_READ_EXCEPTION = 1 << 5;
    /**
     * read all methods, even if they are glitch
     */
    public static final int KEEP_ALL_METHODS = 1 << 6;
    /**
     * keep clinit method when {@link #SKIP_DEBUG}
     */
    public static final int KEEP_CLINIT = 1 << 7;

    /**
     * Enable debug log
     */
    public static final int ENABLE_DEBUG_LOG = 1 << 16;

    /**
     * Single Dex Reader
     */
    private static class SingleDexReader {

        // private static final int REVERSE_ENDIAN_CONSTANT = 0x78563412;

        static final int DBG_END_SEQUENCE = 0x00;
        static final int DBG_ADVANCE_PC = 0x01;
        static final int DBG_ADVANCE_LINE = 0x02;
        static final int DBG_START_LOCAL = 0x03;
        static final int DBG_START_LOCAL_EXTENDED = 0x04;
        static final int DBG_END_LOCAL = 0x05;
        static final int DBG_RESTART_LOCAL = 0x06;
        static final int DBG_SET_PROLOGUE_END = 0x07;
        static final int DBG_SET_EPILOGUE_BEGIN = 0x08;
        static final int DBG_SET_FILE = 0x09;
        static final int DBG_FIRST_SPECIAL = 0x0a;
        static final int DBG_LINE_BASE = -4;
        static final int DBG_LINE_RANGE = 15;
        private static final int MAGIC_035 = 0x00353330;
        private static final int ENDIAN_CONSTANT = 0x12345678;
        private static final int VALUE_BYTE = 0;
        private static final int VALUE_SHORT = 2;
        private static final int VALUE_CHAR = 3;
        private static final int VALUE_INT = 4;
        private static final int VALUE_LONG = 6;
        private static final int VALUE_FLOAT = 16;
        private static final int VALUE_DOUBLE = 17;
        private static final int VALUE_STRING = 23;
        private static final int VALUE_TYPE = 24;
        private static final int VALUE_FIELD = 25;
        private static final int VALUE_METHOD = 26;
        private static final int VALUE_ENUM = 27;
        private static final int VALUE_ARRAY = 28;
        private static final int VALUE_ANNOTATION = 29;
        private static final int VALUE_NULL = 30;
        private static final int VALUE_BOOLEAN = 31;
        final ByteBuffer annotationSetRefListIn;
        final ByteBuffer annotationsDirectoryItemIn;
        final ByteBuffer annotationSetItemIn;
        final ByteBuffer annotationItemIn;
        final ByteBuffer classDataIn;
        final ByteBuffer codeItemIn;
        final ByteBuffer encodedArrayItemIn;
        final ByteBuffer stringIdIn;
        final ByteBuffer typeIdIn;
        final ByteBuffer protoIdIn;
        final ByteBuffer fieldIdIn;
        final ByteBuffer methodIdIn;
        final ByteBuffer classDefIn;
        final ByteBuffer typeListIn;
        final ByteBuffer stringDataIn;
        final ByteBuffer debugInfoIn;
        final int string_ids_size;
        final int type_ids_size;
        final int field_ids_size;
        final int method_ids_size;
        final private int class_defs_size;

        /**
         * read dex from a {@link ByteBuffer}.
         *
         * @param in data
         */
        public SingleDexReader(ByteBuffer in) {
            in.position(0);
            in = in.asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN);

            // skip magic
            ByteBuffers.skip(in, 4);

            // version
            if ((in.getInt() & 0x00FFFFFF) != MAGIC_035) {
                WARN("unexpected version");
            }

            // skip uint checksum
            // and 20 bytes signature
            // and uint file_size
            ByteBuffers.skip(in, 4 + 20 + 4);

            if (in.getInt() != 0x70) {
                WARN("unexpected header size");
            }

            if (in.getInt() != ENDIAN_CONSTANT) {
                WARN("unexpected endian");
            }

            // skip uint link_size
            // and uint link_off
            // and uint map_off
            ByteBuffers.skip(in, 4 + 4 + 4);

            string_ids_size = in.getInt();
            int string_ids_off = in.getInt();
            type_ids_size = in.getInt();
            int type_ids_off = in.getInt();
            int proto_ids_size = in.getInt();
            int proto_ids_off = in.getInt();
            field_ids_size = in.getInt();
            int field_ids_off = in.getInt();
            method_ids_size = in.getInt();
            int method_ids_off = in.getInt();
            class_defs_size = in.getInt();
            int class_defs_off = in.getInt();
            // skip uint data_size data_off

            stringIdIn = ByteBuffers.slice(in, string_ids_off, string_ids_size * 4);
            typeIdIn = ByteBuffers.slice(in, type_ids_off, type_ids_size * 4);
            protoIdIn = ByteBuffers.slice(in, proto_ids_off, proto_ids_size * 12);
            fieldIdIn = ByteBuffers.slice(in, field_ids_off, field_ids_size * 8);
            methodIdIn = ByteBuffers.slice(in, method_ids_off, method_ids_size * 8);
            classDefIn = ByteBuffers.slice(in, class_defs_off, class_defs_size * 32);

            in.position(0);
            annotationsDirectoryItemIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            annotationSetItemIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            annotationItemIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            annotationSetRefListIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            classDataIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            codeItemIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            stringDataIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            encodedArrayItemIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            typeListIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            debugInfoIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        }

        static void WARN(String fmt, Object... args) {
            System.err.println(String.format(fmt, args));
        }

        private void DEBUG_DEBUG(String fmt, Object... args) {
            if (enableDebugLog) System.out.println(String.format(fmt, args));
        }

        private void read_debug_info(int offset, int regSize, boolean isStatic, Method method,
                                     Map<Integer, DexLabel> labelMap, DexDebugVisitor dcv) {
            ByteBuffer in = debugInfoIn;
            in.position(offset);
            int address = 0;
            int line = ByteBuffers.readULeb128i(in);
            int szParams = ByteBuffers.readULeb128i(in);
            LocalEntry lastEntryForReg[] = new LocalEntry[regSize];
            int argsSize = 0;
            for (String paramType : method.getParameterTypes()) {
                if (paramType.equals("J") || paramType.equals("D")) {
                    argsSize += 2;
                } else {
                    argsSize += 1;
                }
            }
            int curReg = regSize - argsSize;
            if (!isStatic) {
                // Start off with implicit 'this' entry
                LocalEntry thisEntry = new LocalEntry("this", method.getOwner(), null);
                lastEntryForReg[curReg - 1] = thisEntry;
                // dcv.visitParameterName(curReg - 1, "this");
                DEBUG_DEBUG("v%d :%s, %s", curReg - 1, "this", method.getOwner());
            }

            String[] params = method.getParameterTypes();
            for (int i = 0; i < szParams; i++) {
                String paramType = params[i];
                LocalEntry le;

                int nameIdx = ByteBuffers.readStringIndex(in);
                String name = getString(nameIdx);
                le = new LocalEntry(name, paramType);
                lastEntryForReg[curReg] = le;
                if (name != null) {
                    dcv.visitParameterName(i, name);
                }
                DEBUG_DEBUG("v%d :%s, %s", curReg, name, paramType);
                curReg += 1;
                if (paramType.equals("J") || paramType.equals("D")) {
                    curReg += 1;
                }
            }

            for (; ; ) {
                int opcode = in.get() & 0xff;

                switch (opcode) {
                    case DBG_START_LOCAL: {
                        int reg = ByteBuffers.readULeb128i(in);
                        int nameIdx = ByteBuffers.readStringIndex(in);
                        int typeIdx = ByteBuffers.readStringIndex(in);
                        String name = getString(nameIdx);
                        String type = getType(typeIdx);
                        DEBUG_DEBUG("Start: v%d :%s, %s", reg, name, type);
                        LocalEntry le = new LocalEntry(name, type);
                        lastEntryForReg[reg] = le;
                        ByteBuffers.order(labelMap, address);
                        dcv.visitStartLocal(reg, labelMap.get(address), name, type, null);
                    }
                    break;

                    case DBG_START_LOCAL_EXTENDED: {
                        int reg = ByteBuffers.readULeb128i(in);
                        int nameIdx = ByteBuffers.readStringIndex(in);
                        int typeIdx = ByteBuffers.readStringIndex(in);
                        int sigIdx = ByteBuffers.readStringIndex(in);
                        String name = getString(nameIdx);
                        String type = getType(typeIdx);
                        String signature = getString(sigIdx);
                        DEBUG_DEBUG("Start: v%d :%s, %s // %s", reg, name, type, signature);
                        LocalEntry le = new LocalEntry(name, type, signature);
                        ByteBuffers.order(labelMap, address);
                        dcv.visitStartLocal(reg, labelMap.get(address), name, type, signature);
                        lastEntryForReg[reg] = le;
                    }
                    break;

                    case DBG_RESTART_LOCAL: {
                        int reg = ByteBuffers.readULeb128i(in);
                        LocalEntry le = lastEntryForReg[reg];
                        if (le == null) {
                            throw new RuntimeException("Encountered RESTART_LOCAL on new v" + reg);
                        }
                        if (le.signature == null) {
                            DEBUG_DEBUG("Start: v%d :%s, %s", reg, le.name, le.type);
                        } else {
                            DEBUG_DEBUG("Start: v%d :%s, %s // %s", reg, le.name, le.type, le.signature);
                        }
                        ByteBuffers.order(labelMap, address);
                        dcv.visitRestartLocal(reg, labelMap.get(address));
                    }
                    break;

                    case DBG_END_LOCAL: {
                        int reg = ByteBuffers.readULeb128i(in);
                        LocalEntry le = lastEntryForReg[reg];
                        if (le == null) {
                            throw new RuntimeException("Encountered RESTART_LOCAL on new v" + reg);
                        }
                        if (le.signature == null) {
                            DEBUG_DEBUG("End: v%d :%s, %s", reg, le.name, le.type);
                        } else {
                            DEBUG_DEBUG("End: v%d :%s, %s // %s", reg, le.name, le.type, le.signature);
                        }
                        ByteBuffers.order(labelMap, address);
                        dcv.visitEndLocal(reg, labelMap.get(address));
                    }
                    break;

                    case DBG_END_SEQUENCE:
                        // all done
                        return;

                    case DBG_ADVANCE_PC:
                        address += ByteBuffers.readULeb128i(in);
                        break;

                    case DBG_ADVANCE_LINE:
                        line += ByteBuffers.readLeb128i(in);
                        break;

                    case DBG_SET_PROLOGUE_END:
                        ByteBuffers.order(labelMap, address);
                        dcv.visitPrologue(labelMap.get(address));
                        break;
                    case DBG_SET_EPILOGUE_BEGIN:
                        ByteBuffers.order(labelMap, address);
                        dcv.visitEpiogue(labelMap.get(address));
                        break;
                    case DBG_SET_FILE:
                        // skip
                        break;

                    default:
                        if (opcode < DBG_FIRST_SPECIAL) {
                            throw new RuntimeException("Invalid extended opcode encountered " + opcode);
                        }

                        int adjOpcode = opcode - DBG_FIRST_SPECIAL;

                        address += adjOpcode / DBG_LINE_RANGE;
                        line += DBG_LINE_BASE + (adjOpcode % DBG_LINE_RANGE);

                        ByteBuffers.order(labelMap, address);
                        dcv.visitLineNumber(line, labelMap.get(address));
                        break;

                }
            }
        }

        private boolean enableDebugLog;

        /**
         * Makes the given visitor visit the dex file.
         *
         * @param dv     visitor
         * @param config config flags, {@link #SKIP_CODE}, {@link #SKIP_DEBUG}, {@link #SKIP_ANNOTATION},
         *               {@link #SKIP_FIELD_CONSTANT}
         */
        public void pipe(DexFileVisitor dv, int config) {
            enableDebugLog = (config & ENABLE_DEBUG_LOG) != 0;

            for (int classIdx = 0; classIdx < class_defs_size; classIdx++) {
                classDefIn.position(classIdx * 32);
                int class_idx = classDefIn.getInt();
                int access_flags = classDefIn.getInt();
                int superclass_idx = classDefIn.getInt();
                int interfaces_off = classDefIn.getInt();
                int source_file_idx = classDefIn.getInt();
                int annotations_off = classDefIn.getInt();
                int class_data_off = classDefIn.getInt();
                int static_values_off = classDefIn.getInt();

                String className = getType(class_idx);
                String superClassName = getType(superclass_idx);
                String[] interfaceNames = getTypeList(interfaces_off);
                try {
                    DexClassVisitor dcv = dv.visit(access_flags, className, superClassName, interfaceNames);
                    if (dcv != null)// 不处理
                    {
                        acceptClass(dcv, source_file_idx, annotations_off, class_data_off, static_values_off, config);
                        dcv.visitEnd();
                    }
                } catch (Exception ex) {
                    DexException dexException = new DexException(ex, "Error process class: [%d]%s", class_idx, className);
                    if (0 != (config & IGNORE_READ_EXCEPTION)) {
                        ExceptionUtil.printStackTraceEx(dexException, 0);
                    } else {
                        throw dexException;
                    }
                }
            }
            dv.visitEnd();
        }

        private Object readEncodedValue(ByteBuffer in) {
            int b = 0xFF & in.get();
            int type = b & 0x1f;
            switch (type) {
                case VALUE_BYTE:
                    return (byte) ByteBuffers.readIntBits(in, b);

                case VALUE_SHORT:
                    return (short) ByteBuffers.readIntBits(in, b);

                case VALUE_INT:
                    return (int) ByteBuffers.readIntBits(in, b);

                case VALUE_LONG:
                    return ByteBuffers.readIntBits(in, b);

                case VALUE_CHAR:
                    return (char) ByteBuffers.readUIntBits(in, b);

                case VALUE_STRING:
                    return getString((int) ByteBuffers.readUIntBits(in, b));

                case VALUE_FLOAT:
                    return Float.intBitsToFloat((int) (ByteBuffers.readFloatBits(in, b) >> 32));

                case VALUE_DOUBLE:
                    return Double.longBitsToDouble(ByteBuffers.readFloatBits(in, b));

                case VALUE_NULL:
                    return null;

                case VALUE_BOOLEAN: {
                    return ((b >> 5) & 0x3) != 0;

                }
                case VALUE_TYPE: {
                    int type_id = (int) ByteBuffers.readUIntBits(in, b);
                    return new DexType(getType(type_id));
                }
                case VALUE_ENUM: {
                    return getField((int) ByteBuffers.readUIntBits(in, b));
                }

                case VALUE_METHOD: {
                    int method_id = (int) ByteBuffers.readUIntBits(in, b);
                    return getMethod(method_id);

                }
                case VALUE_FIELD: {
                    int field_id = (int) ByteBuffers.readUIntBits(in, b);
                    return getField(field_id);
                }
                case VALUE_ARRAY: {
                    return read_encoded_array(in);
                }
                case VALUE_ANNOTATION: {
                    return read_encoded_annotation(in);
                }
                default:
                    throw new DexException("Not support yet.");
            }
        }

        private void acceptClass(DexClassVisitor dcv, int source_file_idx, int annotations_off, int class_data_off,
                                 int static_values_off, int config) {
            if ((config & SKIP_DEBUG) == 0) {
                // 获取源文件
                if (source_file_idx != -1) {
                    dcv.visitSource(this.getString(source_file_idx));
                }
            }

            Map<Integer, Integer> fieldAnnotationPositions;
            Map<Integer, Integer> methodAnnotationPositions;
            Map<Integer, Integer> paramAnnotationPositions;
            if ((config & SKIP_ANNOTATION) == 0) {
                // 获取注解
                fieldAnnotationPositions = new HashMap<>();
                methodAnnotationPositions = new HashMap<>();
                paramAnnotationPositions = new HashMap<>();
                if (annotations_off != 0) { // annotations_directory_item

                    annotationsDirectoryItemIn.position(annotations_off);

                    int class_annotations_off = annotationsDirectoryItemIn.getInt();
                    int field_annotation_size = annotationsDirectoryItemIn.getInt();
                    int method_annotation_size = annotationsDirectoryItemIn.getInt();
                    int parameter_annotation_size = annotationsDirectoryItemIn.getInt();

                    for (int i = 0; i < field_annotation_size; i++) {
                        int field_idx = annotationsDirectoryItemIn.getInt();
                        int field_annotations_offset = annotationsDirectoryItemIn.getInt();
                        fieldAnnotationPositions.put(field_idx, field_annotations_offset);
                    }
                    for (int i = 0; i < method_annotation_size; i++) {
                        int method_idx = annotationsDirectoryItemIn.getInt();
                        int method_annotation_offset = annotationsDirectoryItemIn.getInt();
                        methodAnnotationPositions.put(method_idx, method_annotation_offset);
                    }
                    for (int i = 0; i < parameter_annotation_size; i++) {
                        int method_idx = annotationsDirectoryItemIn.getInt();
                        int parameter_annotation_offset = annotationsDirectoryItemIn.getInt();
                        paramAnnotationPositions.put(method_idx, parameter_annotation_offset);
                    }

                    if (class_annotations_off != 0) {
                        try {
                            read_annotation_set_item(class_annotations_off, dcv);
                        } catch (Exception e) {
                            throw new DexException("error on reading Annotation of class ", e);
                        }
                    }
                }
            } else {
                fieldAnnotationPositions = null;
                methodAnnotationPositions = null;
                paramAnnotationPositions = null;
            }

            if (class_data_off != 0) {
                ByteBuffer in = classDataIn;
                in.position(class_data_off);

                int static_fields = ByteBuffers.readULeb128i(in);
                int instance_fields = ByteBuffers.readULeb128i(in);
                int direct_methods = ByteBuffers.readULeb128i(in);
                int virtual_methods = ByteBuffers.readULeb128i(in);
                {
                    int lastIndex = 0;
                    {
                        Object[] constant = null;
                        if ((config & SKIP_FIELD_CONSTANT) == 0) {
                            if (static_values_off != 0) {
                                constant = read_encoded_array_item(static_values_off);
                            }
                        }
                        for (int i = 0; i < static_fields; i++) {
                            Object value = null;
                            if (constant != null && i < constant.length) {
                                value = constant[i];
                            }
                            lastIndex = acceptField(in, lastIndex, dcv, fieldAnnotationPositions, value, config);
                        }
                    }
                    lastIndex = 0;
                    for (int i = 0; i < instance_fields; i++) {
                        lastIndex = acceptField(in, lastIndex, dcv, fieldAnnotationPositions, null, config);
                    }
                    lastIndex = 0;
                    boolean firstMethod = true;
                    for (int i = 0; i < direct_methods; i++) {
                        lastIndex = acceptMethod(in, lastIndex, dcv, methodAnnotationPositions, paramAnnotationPositions,
                                config, firstMethod);
                        firstMethod = false;
                    }
                    lastIndex = 0;
                    firstMethod = true;
                    for (int i = 0; i < virtual_methods; i++) {
                        lastIndex = acceptMethod(in, lastIndex, dcv, methodAnnotationPositions, paramAnnotationPositions,
                                config, firstMethod);
                        firstMethod = false;
                    }
                }

            }
        }

        private Object[] read_encoded_array_item(int static_values_off) {
            encodedArrayItemIn.position(static_values_off);
            return read_encoded_array(encodedArrayItemIn);
        }

        private Object[] read_encoded_array(ByteBuffer in) {
            int size = ByteBuffers.readULeb128i(in);
            Object[] constant = new Object[size];
            for (int i = 0; i < size; i++) {
                constant[i] = readEncodedValue(in);
            }
            return constant;
        }

        private void read_annotation_set_item(int offset, DexAnnotationAble daa) { // annotation_set_item
            ByteBuffer in = annotationSetItemIn;
            in.position(offset);
            int size = in.getInt();
            for (int j = 0; j < size; j++) {
                int annotation_off = in.getInt();
                read_annotation_item(annotation_off, daa);
            }
        }

        private void read_annotation_item(int annotation_off, DexAnnotationAble daa) {
            ByteBuffer in = annotationItemIn;
            in.position(annotation_off);
            int visibility = 0xFF & in.get();
            DexAnnotationNode annotation = read_encoded_annotation(in);
            annotation.visibility = Visibility.values()[visibility];
            annotation.accept(daa);
        }

        private DexAnnotationNode read_encoded_annotation(ByteBuffer in) {
            int type_idx = ByteBuffers.readULeb128i(in);
            int size = ByteBuffers.readULeb128i(in);
            String _typeString = getType(type_idx);
            DexAnnotationNode ann = new DexAnnotationNode(_typeString, Visibility.RUNTIME);
            for (int i = 0; i < size; i++) {
                int name_idx = ByteBuffers.readULeb128i(in);
                String nameString = getString(name_idx);
                Object value = readEncodedValue(in);
                ann.items.add(new DexAnnotationNode.Item(nameString, value));
            }
            return ann;
        }

        private Field getField(int id) {
            fieldIdIn.position(id * 8);
            int owner_idx = 0xFFFF & fieldIdIn.getShort();
            int type_idx = 0xFFFF & fieldIdIn.getShort();
            int name_idx = fieldIdIn.getInt();
            return new Field(getType(owner_idx), getString(name_idx), getType(type_idx));
        }

        private String[] getTypeList(int offset) {
            if (offset == 0) {
                return new String[0];
            }
            typeListIn.position(offset);
            int size = typeListIn.getInt();
            String[] types = new String[size];
            for (int i = 0; i < size; i++) {
                types[i] = getType(0xFFFF & typeListIn.getShort());
            }
            return types;
        }

        private Method getMethod(int id) {
            methodIdIn.position(id * 8);
            int owner_idx = 0xFFFF & methodIdIn.getShort();
            int proto_idx = 0xFFFF & methodIdIn.getShort();
            int name_idx = methodIdIn.getInt();
            String[] parameterTypes;
            String returnType;

            protoIdIn.position(proto_idx * 12 + 4); // move to position and skip shorty_idx

            int return_type_idx = protoIdIn.getInt();
            int parameters_off = protoIdIn.getInt();

            returnType = getType(return_type_idx);

            parameterTypes = getTypeList(parameters_off);

            return new Method(getType(owner_idx), getString(name_idx), parameterTypes, returnType);

        }

        private String getString(int id) {
            if (id == -1) {
                return null;
            }
            int offset = stringIdIn.getInt(id * 4);
            stringDataIn.position(offset);
            int length = ByteBuffers.readULeb128i(stringDataIn);
            try {
                StringBuilder buff = new StringBuilder((int) (length * 1.5));
                return Mutf8.decode(stringDataIn, buff);
            } catch (UTFDataFormatException e) {
                throw new DexException(e, "fail to load string %d@%08x", id, offset);
            }
        }

        private String getType(int id) {
            if (id == -1) {
                return null;
            }
            return getString(typeIdIn.getInt(id * 4));
        }

        private int acceptField(ByteBuffer in, int lastIndex, DexClassVisitor dcv,
                                Map<Integer, Integer> fieldAnnotationPositions, Object value, int config) {
            int diff = ByteBuffers.readULeb128i(in);
            int field_access_flags = ByteBuffers.readULeb128i(in);
            int field_id = lastIndex + diff;
            Field field = getField(field_id);
            // //////////////////////////////////////////////////////////////
            DexFieldVisitor dfv = dcv.visitField(field_access_flags, field, value);
            if (dfv != null) {
                if ((config & SKIP_ANNOTATION) == 0) {
                    Integer annotation_offset = fieldAnnotationPositions.get(field_id);
                    if (annotation_offset != null) {
                        try {
                            read_annotation_set_item(annotation_offset, dfv);
                        } catch (Exception e) {
                            throw new DexException(e, "while pipe annotation in field:%s.", field.toString());
                        }
                    }
                }
                dfv.visitEnd();
            }
            // //////////////////////////////////////////////////////////////
            return field_id;
        }

        private int acceptMethod(ByteBuffer in, int lastIndex, DexClassVisitor cv, Map<Integer, Integer> methodAnnos,
                                 Map<Integer, Integer> parameterAnnos, int config, boolean firstMethod) {
            int offset = in.position();
            int diff = ByteBuffers.readULeb128i(in);
            int method_access_flags = ByteBuffers.readULeb128i(in);
            int code_off = ByteBuffers.readULeb128i(in);
            int method_id = lastIndex + diff;
            Method method = getMethod(method_id);

            // issue 200, methods may have same signature, we only need to keep the first one
            if (!firstMethod && diff == 0) { // detect a duplicated method
                WARN("GLITCH: duplicated method %s @%08x", method.toString(), offset);
                if ((config & KEEP_ALL_METHODS) == 0) {
                    WARN("WARN: skip method %s @%08x", method.toString(), offset);
                    return method_id;
                }
            }

            // issue 195, a <clinit> or <init> but not marked as ACC_CONSTRUCTOR,
            if (0 == (method_access_flags & DexConstants.ACC_CONSTRUCTOR)
                    && (method.getName().equals("<init>") || method.getName().equals("<clinit>"))) {
                WARN("GLITCH: method %s @%08x not marked as ACC_CONSTRUCTOR", method.toString(), offset);
            }

            try {
                DexMethodVisitor dmv = cv.visitMethod(method_access_flags, method);
                if (dmv != null) {
                    if ((config & SKIP_ANNOTATION) == 0) {
                        Integer annotation_offset = methodAnnos.get(method_id);
                        if (annotation_offset != null) {
                            try {
                                read_annotation_set_item(annotation_offset, dmv);
                            } catch (Exception e) {
                                throw new DexException(e, "while pipe annotation in method:%s.", method.toString());
                            }
                        }
                        Integer parameter_annotation_offset = parameterAnnos.get(method_id);
                        if (parameter_annotation_offset != null) {
                            try {
                                read_annotation_set_ref_list(parameter_annotation_offset, dmv);
                            } catch (Exception e) {
                                throw new DexException(e, "while pipe parameter annotation in method:%s.",
                                        method.toString());
                            }
                        }
                    }
                    if (code_off != 0) {
                        boolean keep = true;
                        if (0 != (SKIP_CODE & config)) {
                            keep = 0 != (KEEP_CLINIT & config) && method.getName().equals("<clinit>");
                        }
                        if (keep) {
                            DexCodeVisitor dcv = dmv.visitCode();
                            if (dcv != null) {
                                try {
                                    acceptCode(code_off, dcv, config, (method_access_flags & DexConstants.ACC_STATIC) != 0,
                                            method);
                                } catch (Exception e) {
                                    throw new DexException(e, "while pipe code in method:[%s] @%08x", method.toString(),
                                            code_off);
                                }
                            }
                        }
                    }
                    dmv.visitEnd();
                }
            } catch (Exception e) {
                throw new DexException(e, "while pipe method:[%s]", method.toString());
            }

            return method_id;
        }

        private void read_annotation_set_ref_list(int parameter_annotation_offset, DexMethodVisitor dmv) {
            ByteBuffer in = annotationSetRefListIn;
            in.position(parameter_annotation_offset);

            int size = in.getInt();
            for (int j = 0; j < size; j++) {
                int param_annotation_offset = in.getInt();
                if (param_annotation_offset == 0) {
                    continue;
                }
                DexAnnotationAble dpav = dmv.visitParameterAnnotation(j);
                try {
                    if (dpav != null) {
                        read_annotation_set_item(param_annotation_offset, dpav);
                    }
                } catch (Exception e) {
                    throw new DexException(e, "while pipe parameter annotation in parameter:[%d]", j);
                }
            }
        }

        static class BadOpException extends RuntimeException {
            public BadOpException(String fmt, Object... args) {
                super(String.format(fmt, args));
            }
        }

        private void findLabels(byte[] insn, BitSet nextBit, BitSet badOps, Map<Integer, DexLabel> labelsMap, Set<Integer> handlers,
                                Method method) {
            Queue<Integer> q = new LinkedList<>();
            q.add(0);
            q.addAll(handlers);
            handlers.clear();
            while (!q.isEmpty()) {
                int offset = q.poll();
                if (nextBit.get(offset)) {
                    continue;
                } else {
                    nextBit.set(offset);
                }
                try {
                    travelInsn(labelsMap, q, insn, offset);
                } catch (IndexOutOfBoundsException indexOutOfRange) {
                    badOps.set(offset);
                    WARN("GLITCH: %04x %s | not enough space for reading instruction", offset, method.toString());
                } catch (BadOpException badOp) {
                    badOps.set(offset);
                    WARN("GLITCH: %04x %s | %s", offset, method.toString(), badOp.getMessage());
                }
            }
        }

        private void travelInsn(Map<Integer, DexLabel> labelsMap, Queue<Integer> q, byte[] insn, int offset) {
            int u1offset = offset * 2;
            if (u1offset >= insn.length) {
                throw new IndexOutOfBoundsException();
            }
            int opcode = 0xFF & insn[u1offset];
            Op op = null;
            if (opcode < Op.ops.length) {
                op = Op.ops[opcode];
            }
            if (op == null || op.format == null) {
                throw new BadOpException("zero-width instruction op=0x%02x", opcode);
            }
            int target;
            boolean canContinue = true;
            if (op.canBranch()) {
                switch (op.format) {
                    case kFmt10t:
                        target = offset + insn[u1offset + 1];
                        if (target < 0 || target * 2 > insn.length) {
                            throw new BadOpException("jump out of insn %s -> %04x", op, target);
                        }
                        q.add(target);
                        ByteBuffers.order(labelsMap, target);
                        break;
                    case kFmt20t:
                    case kFmt21t:
                        target = offset + ByteBuffers.sshort(insn, u1offset + 2);
                        if (target < 0 || target * 2 > insn.length) {
                            throw new BadOpException("jump out of insn %s -> %04x", op, target);
                        }
                        q.add(target);
                        ByteBuffers.order(labelsMap, target);
                        break;
                    case kFmt22t:
                        target = offset + ByteBuffers.sshort(insn, u1offset + 2);

                        int u = ByteBuffers.ubyte(insn, u1offset + 1);
                        boolean cmpSameReg = (u & 0x0F) == ((u >> 4) & 0x0F);
                        boolean skipTarget = false;
                        if (cmpSameReg) {
                            switch (op) {
                                case IF_EQ:
                                case IF_GE:
                                case IF_LE:
                                    // means always jump, equals to goto
                                    canContinue = false;
                                    break;
                                case IF_NE:
                                case IF_GT:
                                case IF_LT:
                                    // means always not jump
                                    skipTarget = true;
                                    break;
                                default:
                                    break;
                            }
                        }
                        if (!skipTarget) {
                            if (target < 0 || target * 2 > insn.length) {
                                throw new BadOpException("jump out of insn %s -> %04x", op, target);
                            }
                            q.add(target);
                            ByteBuffers.order(labelsMap, target);
                        }
                        break;
                    case kFmt30t:
                    case kFmt31t:
                        target = offset + ByteBuffers.sint(insn, u1offset + 2);
                        if (target < 0 || target * 2 > insn.length) {
                            throw new BadOpException("jump out of insn %s -> %04x", op, target);
                        }
                        q.add(target);
                        ByteBuffers.order(labelsMap, target);
                        break;
                    default:
                        break;
                }
            }
            if (op.canSwitch()) {
                ByteBuffers.order(labelsMap, offset + op.format.size);// default
                int u1SwitchData = 2 * (offset + ByteBuffers.sint(insn, u1offset + 2));
                if (u1SwitchData + 2 < insn.length) {

                    switch (insn[u1SwitchData + 1]) {
                        case 0x01: // packed-switch-data
                        {
                            int size = ByteBuffers.ushort(insn, u1SwitchData + 2);
                            int b = u1SwitchData + 8;// targets
                            for (int i = 0; i < size; i++) {
                                target = offset + ByteBuffers.sint(insn, b + i * 4);
                                if (target < 0 || target * 2 > insn.length) {
                                    throw new BadOpException("jump out of insn %s -> %04x", op, target);
                                }
                                q.add(target);
                                ByteBuffers.order(labelsMap, target);
                            }
                            break;
                        }
                        case 0x02:// sparse-switch-data
                        {
                            int size = ByteBuffers.ushort(insn, u1SwitchData + 2);
                            int b = u1SwitchData + 4 + 4 * size;// targets
                            for (int i = 0; i < size; i++) {
                                target = offset + ByteBuffers.sint(insn, b + i * 4);
                                if (target < 0 || target * 2 > insn.length) {
                                    throw new BadOpException("jump out of insn %s -> %04x", op, target);
                                }
                                q.add(target);
                                ByteBuffers.order(labelsMap, target);
                            }
                            break;
                        }
                        default:
                            throw new BadOpException("bad payload for %s", op);
                    }
                } else {
                    throw new BadOpException("bad payload offset for %s", op);
                }
            }

            if (canContinue) {
                int idx = Integer.MAX_VALUE;
                switch (op.indexType) {
                    case kIndexStringRef:
                        if (op.format == InstructionFormat.kFmt31c) {
                            idx = ByteBuffers.uint(insn, u1offset + 2);
                        } else {// other
                            idx = ByteBuffers.ushort(insn, u1offset + 2);
                        }
                        canContinue = idx >= 0 && idx < string_ids_size;
                        break;
                    case kIndexTypeRef:
                        idx = ByteBuffers.ushort(insn, u1offset + 2);
                        canContinue = idx < type_ids_size;
                        break;
                    case kIndexMethodRef:
                        idx = ByteBuffers.ushort(insn, u1offset + 2);
                        canContinue = idx < method_ids_size;
                        break;
                    case kIndexFieldRef:
                        idx = ByteBuffers.ushort(insn, u1offset + 2);
                        canContinue = idx < field_ids_size;
                        break;
                    default:
                }
                if (!canContinue) {
                    throw new BadOpException("index-out-of-range for %s index: %d", op, idx);
                }
            }

            if (canContinue && op.canContinue()) {
                if (op == Op.NOP) {
                    switch (insn[u1offset + 1]) {
                        case 0x00:
                            q.add(offset + op.format.size);
                            break;
                        case 0x01: {
                            int size = ByteBuffers.ushort(insn, u1offset + 2);
                            q.add(offset + (size * 2) + 4);
                            break;
                        }
                        case 0x02: {
                            int size = ByteBuffers.ushort(insn, u1offset + 2);
                            q.add(offset + (size * 4) + 2);
                            break;
                        }
                        case 0x03: {
                            int element_width = ByteBuffers.ushort(insn, u1offset + 2);
                            int size = ByteBuffers.uint(insn, u1offset + 4);
                            q.add(offset + (size * element_width + 1) / 2 + 4);
                            break;
                        }
                    }
                } else {
                    q.add(offset + op.format.size);
                }
            }
        }

        private void findTryCatch(ByteBuffer in, DexCodeVisitor dcv, int tries_size, int insn_size,
                                  Map<Integer, DexLabel> labelsMap, Set<Integer> handlers) {
            int encoded_catch_handler_list = in.position() + tries_size * 8;
            ByteBuffer handlerIn = in.duplicate().order(ByteOrder.LITTLE_ENDIAN);
            for (int i = 0; i < tries_size; i++) { // try_item
                int start_addr = in.getInt();
                int insn_count = 0xFFFF & in.getShort();
                int handler_offset = 0xFFFF & in.getShort();
                if (start_addr > insn_size) {
                    continue;
                }
                ByteBuffers.order(labelsMap, start_addr);
                int end = start_addr + insn_count;
                ByteBuffers.order(labelsMap, end);

                handlerIn.position(encoded_catch_handler_list + handler_offset);// move to encoded_catch_handler

                boolean catchAll = false;
                int listSize = ByteBuffers.readLeb128i(handlerIn);
                int handlerCount = listSize;
                if (listSize <= 0) {
                    listSize = -listSize;
                    handlerCount = listSize + 1;
                    catchAll = true;
                }
                DexLabel labels[] = new DexLabel[handlerCount];
                String types[] = new String[handlerCount];
                for (int k = 0; k < listSize; k++) {
                    int type_id = ByteBuffers.readULeb128i(handlerIn);
                    int handler = ByteBuffers.readULeb128i(handlerIn);
                    ByteBuffers.order(labelsMap, handler);
                    handlers.add(handler);
                    types[k] = getType(type_id);
                    labels[k] = labelsMap.get(handler);
                }
                if (catchAll) {
                    int handler = ByteBuffers.readULeb128i(handlerIn);
                    ByteBuffers.order(labelsMap, handler);
                    handlers.add(handler);
                    labels[listSize] = labelsMap.get(handler);
                }
                dcv.visitTryCatch(labelsMap.get(start_addr), labelsMap.get(end), labels, types);
            }
        }

        /* package */void acceptCode(int code_off, DexCodeVisitor dcv, int config, boolean isStatic, Method method) {
            ByteBuffer in = codeItemIn;
            in.position(code_off);
            int registers_size = 0xFFFF & in.getShort();
            in.getShort();// ins_size ushort
            in.getShort();// outs_size ushort
            int tries_size = 0xFFFF & in.getShort();
            int debug_info_off = in.getInt();
            int insn = in.getInt();

            byte[] insnArray = new byte[insn * 2];
            in.get(insnArray);
            dcv.visitRegister(registers_size);
            BitSet nextInsn = new BitSet();
            Map<Integer, DexLabel> labelsMap = new TreeMap<>();
            Set<Integer> handlers = new HashSet<>();
            // 处理异常处理
            if (tries_size > 0) {
                if ((insn & 0x01) != 0) {// skip padding
                    in.getShort();
                }
                findTryCatch(in, dcv, tries_size, insn, labelsMap, handlers);
            }
            // 处理debug信息
            if (debug_info_off != 0 && (0 == (config & SKIP_DEBUG))) {
                DexDebugVisitor ddv = dcv.visitDebug();
                if (ddv != null) {
                    read_debug_info(debug_info_off, registers_size, isStatic, method, labelsMap, ddv);
                    ddv.visitEnd();
                }
            }

            BitSet badOps = new BitSet();
            findLabels(insnArray, nextInsn, badOps, labelsMap, handlers, method);
            acceptInsn(insnArray, dcv, nextInsn, badOps, labelsMap);
            dcv.visitEnd();
        }

        // 处理指令
        private void acceptInsn(byte[] insn, DexCodeVisitor dcv, BitSet nextInsn, BitSet badOps, Map<Integer, DexLabel> labelsMap) {
            Iterator<Integer> labelOffsetIterator = labelsMap.keySet().iterator();
            Integer nextLabelOffset = labelOffsetIterator.hasNext() ? labelOffsetIterator.next() : null;
            Op[] values = Op.ops;
            for (int offset = nextInsn.nextSetBit(0); offset >= 0; offset = nextInsn.nextSetBit(offset + 1)) {
                // issue 65, a label may `inside` an instruction
                // visit all label with offset <= currentOffset
                while (nextLabelOffset != null) {
                    if (nextLabelOffset <= offset) {
                        dcv.visitLabel(labelsMap.get(nextLabelOffset));
                        nextLabelOffset = labelOffsetIterator.hasNext() ? labelOffsetIterator.next() : null;
                    } else {
                        // the label is after this instruction
                        break;
                    }
                }

                if (badOps.get(offset)) {
                    dcv.visitStmt0R(Op.BAD_OP);
                    continue;
                }

                int u1offset = offset * 2;
                int opcode = 0xFF & insn[u1offset];

                Op op = values[opcode];

                int a, b, c, target;
                switch (op.format) {
                    // case kFmt00x: break;
                    case kFmt10x:
                        dcv.visitStmt0R(op);
                        break;

                    case kFmt11x:
                        dcv.visitStmt1R(op, 0xFF & insn[u1offset + 1]);
                        break;
                    case kFmt12x:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        dcv.visitStmt2R(op, a & 0xF, a >> 4);
                        break;
                    // case kFmt20bc:break;
                    case kFmt10t:
                        target = offset + insn[u1offset + 1];
                        dcv.visitJumpStmt(op, -1, -1, labelsMap.get(target));
                        break;
                    case kFmt20t:
                        target = offset + ByteBuffers.sshort(insn, u1offset + 2);
                        dcv.visitJumpStmt(op, -1, -1, labelsMap.get(target));
                        break;
                    case kFmt21t:
                        target = offset + ByteBuffers.sshort(insn, u1offset + 2);
                        dcv.visitJumpStmt(op, ByteBuffers.ubyte(insn, u1offset + 1), -1, labelsMap.get(target));
                        break;
                    case kFmt22t:
                        target = offset + ByteBuffers.sshort(insn, u1offset + 2);
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = a & 0x0F;
                        c = a >> 4;
                        boolean ignore = false;
                        if (b == c) {
                            switch (op) {
                                case IF_EQ:
                                case IF_GE:
                                case IF_LE:
                                    // means always jump, equals to goto
                                    dcv.visitJumpStmt(Op.GOTO, 0, 0, labelsMap.get(target));
                                    ignore = true;
                                    break;
                                case IF_NE:
                                case IF_GT:
                                case IF_LT:
                                    // means always not jump
                                    ignore = true;
                                    break;
                                default:
                                    break;
                            }
                        }
                        if (!ignore) {
                            dcv.visitJumpStmt(op, b, c, labelsMap.get(target));
                        }
                        break;
                    case kFmt30t:
                        target = offset + ByteBuffers.sint(insn, u1offset + 2);
                        dcv.visitJumpStmt(op, -1, -1, labelsMap.get(target));
                        break;
                    case kFmt31t:
                        target = offset + ByteBuffers.sint(insn, u1offset + 2);
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        int u1SwitchData = 2 * target;
                        if (op == Op.FILL_ARRAY_DATA) {
                            int element_width = ByteBuffers.ushort(insn, u1SwitchData + 2);
                            int size = ByteBuffers.uint(insn, u1SwitchData + 4);
                            switch (element_width) {
                                case 1: {
                                    byte[] data = new byte[size];
                                    System.arraycopy(insn, u1SwitchData + 8, data, 0, size);
                                    dcv.visitFillArrayDataStmt(op, a, data);
                                }
                                break;
                                case 2: {
                                    short[] data = new short[size];
                                    for (int i = 0; i < size; i++) {
                                        data[i] = (short) ByteBuffers.sshort(insn, u1SwitchData + 8 + 2 * i);
                                    }
                                    dcv.visitFillArrayDataStmt(op, a, data);
                                }
                                break;
                                case 4: {
                                    int[] data = new int[size];
                                    for (int i = 0; i < size; i++) {
                                        data[i] = ByteBuffers.sint(insn, u1SwitchData + 8 + 4 * i);
                                    }
                                    dcv.visitFillArrayDataStmt(op, a, data);
                                }
                                break;
                                case 8: {
                                    long[] data = new long[size];
                                    for (int i = 0; i < size; i++) {
                                        int t = u1SwitchData + 8 + 8 * i;
                                        long z = 0;
                                        z |= ((long) ByteBuffers.ushort(insn, t));
                                        z |= ((long) ByteBuffers.ushort(insn, t + 2)) << 16;
                                        z |= ((long) ByteBuffers.ushort(insn, t + 4)) << 32;
                                        z |= ((long) ByteBuffers.ushort(insn, t + 6)) << 48;
                                        data[i] = z;
                                    }
                                    dcv.visitFillArrayDataStmt(op, a, data);
                                }
                                break;
                            }
                        } else if (op == Op.SPARSE_SWITCH) {
                            int size = ByteBuffers.sshort(insn, u1SwitchData + 2);
                            int keys[] = new int[size];
                            DexLabel labels[] = new DexLabel[size];
                            int z = u1SwitchData + 4;
                            for (int i = 0; i < size; i++) {
                                keys[i] = ByteBuffers.sint(insn, z + i * 4);
                            }
                            z += size * 4;
                            for (int i = 0; i < size; i++) {
                                labels[i] = labelsMap.get(offset + ByteBuffers.sint(insn, z + i * 4));
                            }
                            dcv.visitSparseSwitchStmt(op, a, keys, labels);
                        } else {
                            int size = ByteBuffers.sshort(insn, u1SwitchData + 2);
                            int first_key = ByteBuffers.sint(insn, u1SwitchData + 4);
                            DexLabel labels[] = new DexLabel[size];
                            int z = u1SwitchData + 8;
                            for (int i = 0; i < size; i++) {
                                labels[i] = labelsMap.get(offset + ByteBuffers.sint(insn, z));
                                z += 4;
                            }
                            dcv.visitPackedSwitchStmt(op, a, first_key, labels);
                        }
                        break;
                    case kFmt21c:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ushort(insn, u1offset + 2);
                        switch (op.indexType) {
                            case kIndexStringRef:
                                dcv.visitConstStmt(op, a, getString(b));
                                break;
                            case kIndexFieldRef:
                                dcv.visitFieldStmt(op, a, -1, getField(b));
                                break;
                            case kIndexTypeRef:
                                if (op == Op.CONST_CLASS) {
                                    dcv.visitConstStmt(op, a, new DexType(getType(b)));
                                } else {
                                    dcv.visitTypeStmt(op, a, -1, getType(b));
                                }
                                break;
                            default:
                                break;
                        }
                        break;
                    case kFmt22c:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ushort(insn, u1offset + 2);
                        switch (op.indexType) {
                            case kIndexFieldRef:
                                dcv.visitFieldStmt(op, a & 0xF, a >> 4, getField(b));
                                break;
                            case kIndexTypeRef:
                                dcv.visitTypeStmt(op, a & 0xF, a >> 4, getType(b));
                                break;
                            default:
                                break;
                        }
                        break;
                    case kFmt31c:
                        if (op.indexType == InstructionIndexType.kIndexStringRef) {
                            a = ByteBuffers.ubyte(insn, u1offset + 1);
                            b = ByteBuffers.uint(insn, u1offset + 2);
                            dcv.visitConstStmt(op, a, getString(b));
                        }
                        break;
                    case kFmt35c: {
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ushort(insn, u1offset + 2);
                        int dc = ByteBuffers.ubyte(insn, u1offset + 4); // DC
                        int fe = ByteBuffers.ubyte(insn, u1offset + 5); // FE

                        int regs[] = new int[a >> 4];
                        switch (a >> 4) {
                            case 5:
                                regs[4] = a & 0xF;// G
                            case 4:
                                regs[3] = 0xF & (fe >> 4);// F
                            case 3:
                                regs[2] = 0xF & (fe);// E
                            case 2:
                                regs[1] = 0xF & (dc >> 4);// D
                            case 1:
                                regs[0] = 0xF & (dc);// C
                        }
                        if (op.indexType == InstructionIndexType.kIndexTypeRef) {
                            dcv.visitFilledNewArrayStmt(op, regs, getType(b));
                        } else {
                            dcv.visitMethodStmt(op, regs, getMethod(b));
                        }
                    }
                    break;
                    case kFmt3rc: {
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ushort(insn, u1offset + 2);
                        c = ByteBuffers.ushort(insn, u1offset + 4);
                        int regs[] = new int[a];
                        for (int i = 0; i < a; i++) {
                            regs[i] = c + i;
                        }
                        if (op.indexType == InstructionIndexType.kIndexTypeRef) {
                            dcv.visitFilledNewArrayStmt(op, regs, getType(b));
                        } else {
                            dcv.visitMethodStmt(op, regs, getMethod(b));
                        }
                    }
                    break;
                    case kFmt22x:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ushort(insn, u1offset + 2);
                        dcv.visitStmt2R(op, a, b);
                        break;
                    case kFmt23x:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ubyte(insn, u1offset + 2);
                        c = ByteBuffers.ubyte(insn, u1offset + 3);
                        dcv.visitStmt3R(op, a, b, c);
                        break;
                    case kFmt32x:
                        a = ByteBuffers.ushort(insn, u1offset + 2);
                        b = ByteBuffers.ushort(insn, u1offset + 4);
                        dcv.visitStmt2R(op, a, b);
                        break;
                    case kFmt11n:
                        a = insn[u1offset + 1];
                        dcv.visitConstStmt(op, a & 0xF, a >> 4);
                        break;
                    case kFmt21h:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.sshort(insn, u1offset + 2);
                        if (op == Op.CONST_HIGH16) {
                            dcv.visitConstStmt(op, a, b << 16);
                        } else {
                            dcv.visitConstStmt(op, a, ((long) b) << 48);
                        }
                        break;
                    case kFmt21s:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.sshort(insn, u1offset + 2);
                        if (op == Op.CONST_16) {
                            dcv.visitConstStmt(op, a, b);
                        } else {
                            dcv.visitConstStmt(op, a, (long) b);
                        }
                        break;
                    case kFmt22b:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.ubyte(insn, u1offset + 2);
                        c = ByteBuffers.sbyte(insn, u1offset + 3);
                        dcv.visitStmt2R1N(op, a, b, c);
                        break;
                    case kFmt22s:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.sshort(insn, u1offset + 2);
                        dcv.visitStmt2R1N(op, a & 0xF, a >> 4, b);
                        break;
                    // case kFmt22cs:break;
                    case kFmt31i:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        b = ByteBuffers.sint(insn, u1offset + 2);
                        if (op == Op.CONST) {
                            dcv.visitConstStmt(op, a, b);
                        } else {
                            dcv.visitConstStmt(op, a, (long) b);
                        }
                        break;
                    case kFmt51l:
                        a = ByteBuffers.ubyte(insn, u1offset + 1);
                        long z = 0;
                        z |= ((long) ByteBuffers.ushort(insn, u1offset + 2));
                        z |= ((long) ByteBuffers.ushort(insn, u1offset + 4)) << 16;
                        z |= ((long) ByteBuffers.ushort(insn, u1offset + 6)) << 32;
                        z |= ((long) ByteBuffers.ushort(insn, u1offset + 8)) << 48;
                        dcv.visitConstStmt(op, a, z);
                        break;
                }
            }

            while (nextLabelOffset != null) {
                dcv.visitLabel(labelsMap.get(nextLabelOffset));
                if (labelOffsetIterator.hasNext()) {
                    nextLabelOffset = labelOffsetIterator.next();
                } else {
                    break;
                }
            }
        }

        /**
         * An entry in the resulting locals table
         */
        static private class LocalEntry {
            public final String name, type, signature;

            private LocalEntry(String name, String type) {
                this.name = name;
                this.type = type;
                this.signature = null;
            }

            private LocalEntry(String name, String type, String signature) {
                this.name = name;
                this.type = type;
                this.signature = signature;
            }
        }
    }
}
