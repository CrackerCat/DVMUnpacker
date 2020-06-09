package com.virjar.dvmunpacker.unpacker.utils;

import com.google.common.collect.Lists;

import java.util.Collections;
import java.util.List;

/**
 * Created by virjar on 2018/4/26.<br>
 */

public class CommonUtil {

    public static List<String> splitWithWidth(String input, int width) {
        if (input == null) {
            return Collections.emptyList();
        }
        int size = (input.length() + width - 1) / width;
        List<String> ret = Lists.newArrayListWithExpectedSize(size);
        for (int i = 0; i < size; i++) {
            int end = (size + 1) * width;
            if (end >= input.length()) {
                end = input.length() - 1;
            }
            ret.add(input.substring(i * size, end));
        }
        return ret;
    }

    private static String primitiveTypeLabel(char typeChar) {
        switch (typeChar) {
            case 'B':
                return "byte";
            case 'C':
                return "char";
            case 'D':
                return "double";
            case 'F':
                return "float";
            case 'I':
                return "int";
            case 'J':
                return "long";
            case 'S':
                return "short";
            case 'V':
                return "void";
            case 'Z':
                return "boolean";
            default:
                return "UNKNOWN";
        }
    }

    /**
     * Converts a type descriptor to human-readable "dotted" form.  For
     * example, "Ljava/lang/String;" becomes "java.lang.String", and
     * "[I" becomes "int[]".  Also converts '$' to '.', which means this
     * form can't be converted back to a descriptor.
     * 这段代码是虚拟机里面抠出来的，c++转java
     */
    public static String descriptorToDot(String str) {
        int targetLen = str.length();
        int offset = 0;
        int arrayDepth = 0;


        /* strip leading [s; will be added to end */
        while (targetLen > 1 && str.charAt(offset) == '[') {
            offset++;
            targetLen--;
        }
        arrayDepth = offset;

        if (targetLen == 1) {
            /* primitive type */
            str = primitiveTypeLabel(str.charAt(offset));
            offset = 0;
            targetLen = str.length();
        } else {
            /* account for leading 'L' and trailing ';' */
            if (targetLen >= 2 && str.charAt(offset) == 'L' &&
                    str.charAt(offset + targetLen - 1) == ';') {
                targetLen -= 2;
                offset++;
            }
        }
        StringBuilder newStr = new StringBuilder(targetLen + arrayDepth * 2);
        /* copy class name over */
        int i;
        for (i = 0; i < targetLen; i++) {
            char ch = str.charAt(offset + i);
            newStr.append((ch == '/') ? '.' : ch);
            //do not convert "$" to ".", ClassLoader.loadClass use "$"
            //newStr.append((ch == '/' || ch == '$') ? '.' : ch);
        }
        /* add the appropriate number of brackets for arrays */
        //感觉源代码这里有bug？？？？，arrayDepth会被覆盖，之后的assert应该有问题
        int tempArrayDepth = arrayDepth;
        while (tempArrayDepth-- > 0) {
            newStr.append('[');
            newStr.append(']');
        }
        return new String(newStr);
    }

    public static String safeToString(Object object) {
        if (object == null) {
            return "null";
        }
        return object.toString();
    }



}
