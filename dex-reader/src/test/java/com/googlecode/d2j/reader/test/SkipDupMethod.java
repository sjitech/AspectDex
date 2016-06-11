package com.googlecode.d2j.reader.test;


import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.reader.DexReader;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

public class SkipDupMethod {
    @Test
    public void test() throws IOException {
        InputStream is = SkipDupMethod.class.getClassLoader().getResourceAsStream("i200.dex");
        Assert.assertNotNull(is);
        DexReader reader = new DexReader(is);
        DexFileNode dfn1 = new DexFileNode();
        reader.pipe(dfn1, DexReader.KEEP_ALL_METHODS);
        DexFileNode dfn2 = new DexFileNode();
        reader.pipe(dfn2, 0);
        Assert.assertTrue(dfn1.clzs.get(0).methods.size() > dfn2.clzs.get(0).methods.size());

    }
}
