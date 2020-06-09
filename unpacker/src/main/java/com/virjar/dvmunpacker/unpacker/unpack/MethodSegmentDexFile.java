package com.virjar.dvmunpacker.unpacker.unpack;

import com.virjar.baksmalisrc.dexlib2.Opcodes;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedClassDef;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedDexFile;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexReader;
import com.virjar.baksmalisrc.dexlib2.dexbacked.reference.DexBackedFieldReference;
import com.virjar.baksmalisrc.dexlib2.dexbacked.reference.DexBackedMethodReference;
import com.virjar.baksmalisrc.dexlib2.dexbacked.reference.DexBackedStringReference;
import com.virjar.baksmalisrc.dexlib2.dexbacked.reference.DexBackedTypeReference;
import com.virjar.baksmalisrc.dexlib2.iface.reference.Reference;

import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import de.robv.android.xposed.XposedHelpers;

/**
 * Created by virjar on 2018/3/16.<br>
 * 描述一个内存片段，仅仅为了契合baksmali数据读取api，所以放过dex头部检查要求
 * 有本事骂我，女生找我我不生气
 */

public class MethodSegmentDexFile extends DexBackedDexFile {
    private boolean openFlag = false;
    private DexBackedDexFile baseDexFile;
    private int bufLength;

    MethodSegmentDexFile(@Nonnull byte[] buf, DexBackedDexFile baseDexFile) {
        super(baseDexFile.getOpcodes(), (byte[]) XposedHelpers.getObjectField(baseDexFile, "buf"), 0, false);
        openFlag = true;
        this.baseDexFile = baseDexFile;
        XposedHelpers.setObjectField(this, "buf", buf);
        bufLength = buf.length;
    }

    @Override
    public int readSmallUint(int offset) {
        //这里逻辑非常混乱，你看看能不能看懂？
        if (baseDexFile == null) {
            //这个时候读取的是base容器的数据
            return super.readSmallUint(offset);
        }
        //openFlag 用来欺骗baksmali
        if (offset > bufLength || !openFlag) {
            //这个时候读取的是base容器的数据
            return baseDexFile.readSmallUint(offset);
        }
        //这个时候读取的是小缓存的数据
        return super.readSmallUint(offset);
    }

    @Override
    public int readOptionalUint(int offset) {
        if (offset <= bufLength) {
            return super.readOptionalUint(offset);
        }
        return baseDexFile.readOptionalUint(offset);
    }

    @Override
    public int readUshort(int offset) {
        if (offset <= bufLength) {
            return super.readUshort(offset);
        }
        return baseDexFile.readUshort(offset);

    }

    @Override
    public int readUbyte(int offset) {
        if (offset <= bufLength) {
            return super.readUbyte(offset);
        }
        return baseDexFile.readUbyte(offset);
    }

    @Override
    public long readLong(int offset) {
        if (offset <= bufLength) {
            return super.readLong(offset);
        }
        return baseDexFile.readLong(offset);
    }

    @Override
    public int readLongAsSmallUint(int offset) {
        if (offset <= bufLength) {
            return super.readLongAsSmallUint(offset);
        }
        return baseDexFile.readLongAsSmallUint(offset);
    }

    public int readInt(int offset) {
        if (offset <= bufLength) {
            return super.readInt(offset);
        }
        return baseDexFile.readInt(offset);
    }

    @Override
    public int readShort(int offset) {
        if (offset <= bufLength) {
            return super.readShort(offset);
        }
        return baseDexFile.readShort(offset);
    }

    @Override
    public int readByte(int offset) {
        if (offset <= bufLength) {
            return super.readByte(offset);
        }
        return baseDexFile.readByte(offset);
    }

    @Nonnull
    @Override
    public Opcodes getOpcodes() {
        return baseDexFile.getOpcodes();
    }

    @Override
    public boolean isOdexFile() {
        return baseDexFile.isOdexFile();
    }

    @Override
    public boolean hasOdexOpcodes() {
        return baseDexFile.hasOdexOpcodes();
    }

    @Nonnull
    @Override
    public Set<? extends DexBackedClassDef> getClasses() {
        return baseDexFile.getClasses();
    }

    @Override
    public int getStringIdItemOffset(int stringIndex) {
        return baseDexFile.getStringIdItemOffset(stringIndex);
    }

    @Override
    public int getTypeIdItemOffset(int typeIndex) {
        return baseDexFile.getTypeIdItemOffset(typeIndex);
    }

    @Override
    public int getFieldIdItemOffset(int fieldIndex) {
        return baseDexFile.getFieldIdItemOffset(fieldIndex);
    }

    @Override
    public int getMethodIdItemOffset(int methodIndex) {
        return baseDexFile.getMethodIdItemOffset(methodIndex);
    }

    @Override
    public int getProtoIdItemOffset(int protoIndex) {
        return baseDexFile.getProtoIdItemOffset(protoIndex);
    }

    @Override
    public int getClassDefItemOffset(int classIndex) {
        return baseDexFile.getClassDefItemOffset(classIndex);
    }

    @Override
    public int getClassCount() {
        return baseDexFile.getClassCount();
    }

    @Override
    public int getStringCount() {
        return baseDexFile.getStringCount();
    }

    @Override
    public int getTypeCount() {
        return baseDexFile.getTypeCount();
    }

    @Override
    public int getProtoCount() {
        return baseDexFile.getProtoCount();
    }

    @Override
    public int getFieldCount() {
        return baseDexFile.getFieldCount();
    }

    @Override
    public int getMethodCount() {
        return baseDexFile.getMethodCount();
    }

    @Nonnull
    @Override
    public String getString(int stringIndex) {
        return baseDexFile.getString(stringIndex);
    }

    @Nullable
    @Override
    public String getOptionalString(int stringIndex) {
        return baseDexFile.getOptionalString(stringIndex);
    }

    @Nonnull
    @Override
    public String getType(int typeIndex) {
        return baseDexFile.getType(typeIndex);
    }

    @Nullable
    @Override
    public String getOptionalType(int typeIndex) {
        return baseDexFile.getOptionalType(typeIndex);
    }

    @Override
    public List<DexBackedStringReference> getStrings() {
        return baseDexFile.getStrings();
    }

    @Override
    public List<DexBackedTypeReference> getTypes() {
        return baseDexFile.getTypes();
    }

    @Override
    public List<DexBackedMethodReference> getMethods() {
        return baseDexFile.getMethods();
    }

    @Override
    public List<DexBackedFieldReference> getFields() {
        return baseDexFile.getFields();
    }

    @Override
    public List<? extends Reference> getReferences(int referenceType) {
        return baseDexFile.getReferences(referenceType);
    }

    @Nonnull
    @Override
    public DexReader readerAt(int offset) {
        return super.readerAt(offset);
    }


    @Nonnull
    @Override
    protected byte[] getBuf() {
        return (byte[]) XposedHelpers.callMethod(baseDexFile, "getBuf");
    }
}