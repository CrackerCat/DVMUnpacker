package com.virjar.artunpacker;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class SandHookMethodResolver {
    public static int dexMethodIndex = 0;
    private static boolean load = false;

    static {
        init();
    }

    public static void  init(){
        try {
            initInternal();
        } catch (Throwable throwable) {
            //ignore
        }
    }

    private static void initInternal() throws Throwable {
        if (load) {
            return;
        }
        load = true;
        Field artMethodField = ArtUnPacker.getField(Method.class, "artMethod");
        Object testArtMethod = artMethodField.get(ArtUnPacker.testOffsetMethod1);
        Field dexMethodIndexField = null;
        if (ArtUnPacker.hasJavaArtMethod() && testArtMethod.getClass() == ArtUnPacker.artMethodClass) {
//            checkSupportForArtMethod();
//            isArtMethod = true;
            try {
                dexMethodIndexField = ArtUnPacker.getField(ArtUnPacker.artMethodClass, "dexMethodIndex");
            } catch (NoSuchFieldException e) {
                //may 4.4
                dexMethodIndexField = ArtUnPacker.getField(ArtUnPacker.artMethodClass, "methodDexIndex");
            }

        } else if (testArtMethod instanceof Long) {
            // checkSupportForArtMethodId();
//            isArtMethod = false;
            dexMethodIndexField = ArtUnPacker.getField(Method.class, "dexMethodIndex");

        }
        if (dexMethodIndexField != null) {
            dexMethodIndex = (int) dexMethodIndexField.get(ArtUnPacker.testOffsetMethod1);
        }
    }

}
