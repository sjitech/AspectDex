package com.googlecode.d2j.reader;

import com.googlecode.d2j.visitors.DexFileVisitor;

import java.util.List;

public interface BaseDexFileReader {

    void pipe(DexFileVisitor dv);

    List<String> getClassNames();

    void pipe(DexFileVisitor dv, int config);

    void pipe(DexFileVisitor dv, int classIdx, int config);
}
