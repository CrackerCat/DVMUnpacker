package com.virjar.dvmunpacker.unpacker.unpack;

import android.util.Log;
import android.widget.Toast;

import com.google.common.base.Charsets;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.io.ByteStreams;
import com.virjar.baksmalisrc.baksmali.Adaptors.ClassDefinition;
import com.virjar.baksmalisrc.baksmali.Baksmali;
import com.virjar.baksmalisrc.baksmali.BaksmaliOptions;
import com.virjar.baksmalisrc.dexlib2.DexFileFactory;
import com.virjar.baksmalisrc.dexlib2.Opcodes;
import com.virjar.baksmalisrc.dexlib2.analysis.InlineMethodResolver;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedClassDef;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedDexFile;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedMethod;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedMethodImplementation;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexBackedOdexFile;
import com.virjar.baksmalisrc.dexlib2.dexbacked.DexReader;
import com.virjar.baksmalisrc.dexlib2.dexbacked.raw.HeaderItem;
import com.virjar.baksmalisrc.dexlib2.dexbacked.raw.OdexHeaderItem;
import com.virjar.baksmalisrc.dexlib2.iface.ClassDef;
import com.virjar.baksmalisrc.dexlib2.iface.DexFile;
import com.virjar.baksmalisrc.dexlib2.iface.Method;
import com.virjar.baksmalisrc.dexlib2.iface.MethodImplementation;
import com.virjar.baksmalisrc.dexlib2.iface.debug.DebugItem;
import com.virjar.baksmalisrc.dexlib2.iface.reference.MethodReference;
import com.virjar.baksmalisrc.dexlib2.rewriter.DexRewriter;
import com.virjar.baksmalisrc.dexlib2.rewriter.MethodImplementationRewriter;
import com.virjar.baksmalisrc.dexlib2.rewriter.MethodRewriter;
import com.virjar.baksmalisrc.dexlib2.rewriter.Rewriter;
import com.virjar.baksmalisrc.dexlib2.rewriter.RewriterModule;
import com.virjar.baksmalisrc.dexlib2.rewriter.Rewriters;
import com.virjar.baksmalisrc.dexlib2.util.DexUtil;
import com.virjar.baksmalisrc.dexlib2.writer.io.FileDataStore;
import com.virjar.baksmalisrc.dexlib2.writer.pool.DexPool;
import com.virjar.baksmalisrc.util.IndentingWriter;
import com.virjar.dvmunpacker.unpacker.SharedObject;
import com.virjar.dvmunpacker.unpacker.utils.CommonUtil;
import com.virjar.dvmunpacker.unpacker.utils.StringUtils;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentMap;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import de.robv.android.xposed.XposedBridge;


/**
 * Created by virjar on 2018/3/12.<br>
 * 脱壳器,请注意，目前三代壳只支持在dalvik上面脱壳。不支持art模式（这意味着Android5.0以上的版本的手机，暂不支持脱壳），一代壳可以在art和dalvik上面脱壳
 */
public class Dumper {
    private static Set<ClassLoader> dumpedClassLoader = Sets.newConcurrentHashSet();

    static {
        System.loadLibrary("unshellnative");
        initHexMap();
    }

    private static char[] hexMap;

    private static void initHexMap() {
        hexMap = new char[16];
        for (char i = 0; i < 10; i++) {
            hexMap[i] = (char) ('0' + i);
        }
        for (int i = 0; i < 6; i++) {
            hexMap[10 + i] = (char) ('a' + i);
        }
    }


    /**
     * 获取任何一个class对应的dex在内存中的映射，当然该dex可能是格式紊乱的
     *
     * @param loader loader，可以是class对象，也可以是任何一个变量。如果是class对象，则获取class内部的dex，如果是普通对象，则获取class，然后寻找dex
     * @return 一个空间，包含了dex的内存映射
     */
    public static native ByteBuffer originDex(Class<?> loader);


    private static Class<?> resolveLoaderClass(Object loader) {
        if (loader instanceof Class) {
            Class<?> ret = (Class<?>) loader;
            if (ret == Class.class) {
                throw new IllegalStateException("can not create dex from java.lang.Class as a dex locate pointer");
            }
            return ret;
        }
        return loader.getClass();
    }

    /**
     * 使用rewrite功能，修复dex中错误的指令数据
     *
     * @param dexFile     原始的dex model
     * @param classLoader 类加载器，需要使用类加载器获取class，才能定位到对应的method对象
     * @return 基于原始dex文件的一个映射，其中关于method指令的部分将会被替换为内存中的数据
     */
    private static DexFile rewrite(final DexBackedDexFile dexFile, final ClassLoader classLoader) {

        return new DexRewriter(new RewriterModule() {


            @Nonnull
            @Override
            public Rewriter<MethodImplementation> getMethodImplementationRewriter(@Nonnull Rewriters rewriters) {
                return new MethodImplementationRewriter(rewriters) {
                    @Nonnull
                    @Override
                    public MethodImplementation rewrite(@Nonnull MethodImplementation methodImplementation) {
                        return new RewrittenMethodImplementation(methodImplementation) {
                            @Nonnull
                            @Override
                            public Iterable<? extends DebugItem> getDebugItems() {
                                //return super.getDebugItems();
                                // we return an empty collection & prevent call getDebugItems for origin dex file
                                return ImmutableSet.of();
                            }
                        };
                    }
                };
            }

            private ConcurrentMap<String, MethodImplementation> methodImplementationConcurrentMap = Maps.newConcurrentMap();

            @Nonnull
            @Override
            public Rewriter<Method> getMethodRewriter(@Nonnull Rewriters rewriters) {
                return new MethodRewriter(rewriters) {
                    @Nonnull
                    @Override
                    public Method rewrite(@Nonnull final Method value) {
                        if (!(value instanceof DexBackedMethod)) {
                            return super.rewrite(value);
                        }
                        String definingClassString = CommonUtil.descriptorToDot(value.getDefiningClass());
                        if (StringUtils.startsWith(definingClassString, "android.")) {
                            //我们不处理 Android本身的lib库，如果特殊需要，可以单独放开
                            return super.rewrite(value);
                        }
                        Class<?> definingClass;
                        try {
                            definingClass = classLoader.loadClass(definingClassString);
                        } catch (ClassNotFoundException e) {
                            return super.rewrite(value);
                        }
                        if (definingClass.getClassLoader() != classLoader) {
                            return super.rewrite(value);
                        }

                        final Class<?> searchClass = definingClass;
                        final String methodDescriptor = getMethodDescriptor(value);
                        //覆盖 getImplementation
                        return new RewrittenMethod(value) {

                            @Nullable
                            @Override
                            public synchronized MethodImplementation getImplementation() {
                                String key = searchClass.getName() + "." + value.getName() + methodDescriptor;
//
                                if (methodImplementationConcurrentMap.containsKey(key)) {
                                    return methodImplementationConcurrentMap.get(key);
                                }
//                                Log.i("weijia", "rewrite method:" + searchClass.getName() + "." + value.getName() + methodDescriptor);
                                ByteBuffer byteBuffer = methodDataWithDescriptor(methodDescriptor, value.getName(), searchClass);
                                if (byteBuffer == null) {
                                    MethodImplementation ret = super.getImplementation();
                                    if (ret != null) {
                                        methodImplementationConcurrentMap.putIfAbsent(key, ret);
                                    }
                                    return ret;
                                }
                                byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
                                byte[] buffer = new byte[byteBuffer.capacity()];
                                byteBuffer.get(buffer, 0, byteBuffer.capacity());
                                DexBackedMethodImplementation dexBackedMethodImplementation = new DexBackedMethodImplementation(new MethodSegmentDexFile(buffer, dexFile), (DexBackedMethod) value, 0);
                                MethodImplementation ret = rewriters.getMethodImplementationRewriter().rewrite(dexBackedMethodImplementation);
                                methodImplementationConcurrentMap.putIfAbsent(key, ret);
                                return ret;
                            }

                            @Override
                            public int getAccessFlags() {
                                String key = searchClass.getName() + "." + value.getName() + methodDescriptor;
                                int accessFlags = getMethodAccessFlagsWithDescriptor(methodDescriptor, value.getName(), searchClass);
                                if (accessFlags < 0) {
                                    //证明没有找到这个方法
                                    return super.getAccessFlags();
                                }
                                return accessFlags;
                            }
                        };
                    }
                };
            }
        }).rewriteDexFile(dexFile);
    }


    private static DexBackedDexFile createMemoryDexFile(Class loader) {
        ByteBuffer byteBuffer = originDex(loader);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        byte[] buffer = new byte[byteBuffer.capacity()];
        byteBuffer.get(buffer, 0, byteBuffer.capacity());

        if (HeaderItem.verifyMagic(buffer, 0)) {
            return new DexBackedDexFile(Opcodes.forApi(apiLevel()), buffer);
            //a normal dex file
        }
        if (OdexHeaderItem.verifyMagic(buffer, 0)) {
            //this is a odex file
            try {
                ByteArrayInputStream is = new ByteArrayInputStream(buffer);
                DexUtil.verifyOdexHeader(is);
                is.reset();
                byte[] odexBuf = new byte[OdexHeaderItem.ITEM_SIZE];
                ByteStreams.readFully(is, odexBuf);
                int dexOffset = OdexHeaderItem.getDexOffset(odexBuf);
                if (dexOffset > OdexHeaderItem.ITEM_SIZE) {
                    ByteStreams.skipFully(is, dexOffset - OdexHeaderItem.ITEM_SIZE);
                }
                return new DexBackedOdexFile(Opcodes.forApi(Dumper.apiLevel()), odexBuf, ByteStreams.toByteArray(is));
            } catch (IOException e) {
                //while not happen
                throw new RuntimeException(e);
            }
        }
        throw new IllegalStateException("can not find out dex image in vm memory");
    }


    private static boolean makeSureClassValid(ClassLoader classLoader, ClassDef classDef) {
        try {
            classLoader.loadClass(CommonUtil.descriptorToDot(classDef.getType()));
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    private static boolean isDumped(ClassLoader classLoader) {
        if (dumpedClassLoader.contains(classLoader)) {
            return true;
        }
        synchronized (Dumper.class) {
            if (dumpedClassLoader.contains(classLoader)) {
                return true;
            }
            dumpedClassLoader.add(classLoader);
            return false;
        }
    }


    /**
     * 探测一个class是否在对应的classloader中被定义，该classloader可能可以被定义，
     * 但是没有到class被触发define的时机，有些class可能永远没有变
     *
     * @param descriptor  class的descriptor
     * @param classLoader classloader
     * @return 是否被定义
     */
    public static native boolean isClassDefined(String descriptor, ClassLoader classLoader);

    public static void dumDexAsync(final Object loader, final long delayMillis) {
        Class loaderClass = resolveLoaderClass(loader);
        if (dumpedClassLoader.contains(loaderClass.getClassLoader())) {
            XposedBridge.log("dump dex ,this dex always dumped,skip it");
            return;
        }
        new Thread("dexDumpThead") {
            @Override
            public void run() {
                if (delayMillis > 0) {
                    try {
                        Thread.sleep(delayMillis);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
                dumpDexWithoutTempFile(loader);
                // dumpDex(loader);
            }
        }.start();
    }


    private static volatile boolean hasDexMergeTaskExecuted = false;

    /**
     * 同步合并api
     */
    public static void mergeAllDexSync() {
        if (hasDexMergeTaskExecuted) {
            return;
        }
        hasDexMergeTaskExecuted = true;
        File targetDir = new File(SharedObject.context.getFilesDir(), "dumpSmali");
        if (!targetDir.exists()) {
            if (!targetDir.mkdirs()) {
                throw new IllegalStateException("can not create smali output directory for path: " + targetDir.getAbsolutePath());
            }
        }

        if (targetDir.isFile()) {
            throw new IllegalStateException("target smali dump path : " + targetDir.getAbsolutePath() + " is not a directory");
        }
        //收集所有的dex文件信息
        List<File> allDexFiles = Lists.newArrayList();
        for (File dexOutDir : targetDir.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                return pathname.isDirectory();
            }
        })) {
            allDexFiles.addAll(Lists.newArrayList(dexOutDir.listFiles(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return StringUtils.endsWithIgnoreCase(name, ".dex");
                }
            })));
        }

        Set<String> internedClasses = Sets.newHashSet();
        DexPool dexPool = new DexPool(Opcodes.forApi(apiLevel()));
        for (File dexFile : allDexFiles) {
            try {
                Log.i("weijia", "handle file:" + dexFile.getAbsolutePath());
                DexBackedDexFile dexBackedDexFile = DexFileFactory.loadDexFile(dexFile, Opcodes.forApi(apiLevel()));
                Set<? extends DexBackedClassDef> classes = dexBackedDexFile.getClasses();
                for (ClassDef classDef : classes) {
                    if (internedClasses.contains(classDef.getType())) {
                        continue;
                    }
                    Log.i("weijia", "merge class:" + classDef.getType());
                    internedClasses.add(classDef.getType());
                    dexPool.internClass(classDef);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        //写入到文件中
        File file = new File(targetDir, "whole_dump.dex");
        try {
            FileDataStore fileDataStore = new FileDataStore(file);
            dexPool.writeTo(fileDataStore);
            fileDataStore.close();
            Log.i("weijia", "dex merge finished, target file:" + file.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void dumpDexWithoutTempFile(Object loader) {
        Class loaderClass = resolveLoaderClass(loader);
        if (isDumped(loaderClass.getClassLoader())) {
            XposedBridge.log("dump dex ,this dex always dumped,skip it");
            return;
        }
        XposedBridge.log("dump dex ,locate dex image in memory...");
        DexBackedDexFile memoryDexFile = createMemoryDexFile(loaderClass);
        //byte[] buf = (byte[]) XposedHelpers.getObjectField(memoryDexFile, "buf");

        //very fast
        XposedBridge.log("dump dex ,repair method instruction...");
        final ClassLoader classLoader = loaderClass.getClassLoader();
        DexFile dexFile = rewrite(memoryDexFile, classLoader);

        // MemoryDataStore memoryDataStore = new MemoryDataStore(buf.length);
        File dumpDir = resolveDumpDir(memoryDexFile);

        //call newHashSet to trigger classLoader load classes in thread pool
        TreeSet<? extends ClassDef> classes = Sets.newTreeSet(Sets.filter(dexFile.getClasses(), new Predicate<ClassDef>() {
            //有些class是各种常见api的，全部dump太费事儿了，过滤一遍
            ClassDumpSkipStrategy classDumpSkipStrategy = new ClassDumpSkipStrategy();

            @Override
            public boolean apply(final ClassDef input) {
                return !classDumpSkipStrategy.skip(CommonUtil.descriptorToDot(input.getType()));
            }
        }));
        List<? extends ClassDef> classDefsList = Lists.newArrayList(classes);
        //神坑  DexPool 和DexBuilder，如果是从smali编译，那么需要使用DexBuilder，如果是使用内存中的DexFile对象，那么使用DexPool
        DexPool tempDexPool = new DexPool(Opcodes.forApi(apiLevel()));
        for (ClassDef classDef : classDefsList) {
            try {
                Log.i("weijia", "rebuild class:" + CommonUtil.descriptorToDot(classDef.getType()));
                if (!makeSureClassValid(classLoader, classDef)) {
                    Log.i("weijia", "error when define class:" + classDef.getType() + " skipped for rebuild it");
                    continue;
                }
                tempDexPool.internClass(classDef);
            } catch (Exception e) {
                XposedBridge.log(e);
                Log.i("weijia", "error when define class:" + classDef.getType() + " skipped for rebuild it");
            }
        }
        FileDataStore fileDataStore;
        try {
            File targetFile = new File(dumpDir, StringUtils.substringAfterLast(dumpDir.getAbsolutePath(), "/") + "_classes.dex");
            Log.i("weijia", "dump dex ,create dex out put file: " + targetFile.getAbsolutePath());
            if (targetFile.exists() && !targetFile.delete()) {
                Log.i("weijia", "failed to clean dex output file" + targetFile.getAbsolutePath());
            }
            fileDataStore = new FileDataStore(targetFile);
            tempDexPool.writeTo(fileDataStore);
            fileDataStore.close();
            Log.i("weijia", "dex dump finished");
        } catch (IOException e) {
            Log.i("weijia", "can not create dex out file", e);
            throw new RuntimeException(e);
        }
    }


    /**
     * 将对应class对应的dex文件的二进制dump出来,请注意，这个方法非常耗时，可能消耗时间5-10分钟<br>
     * 同时该方法非常消耗cpu和内存，如果你在调用这个方法的过程中，经常任务没有完成就因为内存占用过高被系统杀死，那么请尝试重新启动Android系统，这样可以释放很多内存<br>
     * 该方法将会通过jni和虚拟机直接交互，这可能引发虚拟机崩溃。这个时候请多次重启app调用该方法，我使用了定时保存任务的方式，下次启动app，可以直接从文件中恢复任务，进而避免成功过的任务接触虚拟机。多次运行app，可能最终任务达到成功状态。<br>
     * ps! 虚拟机崩溃不稳定不是我能左右的，这是由于壳自定义了虚拟机加载class的逻辑，导致某些情况下通过classloader load一个class，导致虚拟机闪退了
     *
     * @param loader 该dex文件定义的任何一个class，或者class定义的object
     */
    public static void dumpDex(Object loader) {
        Class loaderClass = resolveLoaderClass(loader);
        if (isDumped(loaderClass.getClassLoader())) {
            Log.e("weijia", "dump dex ,this dex always dumped,skip it");
            return;
        }
        Log.e("weijia", "dump dex ,locate dex image in memory...");
        DexBackedDexFile memoryDexFile = createMemoryDexFile(loaderClass);
        //byte[] buf = (byte[]) XposedHelpers.getObjectField(memoryDexFile, "buf");

        //very fast
        Log.e("weijia", "dump dex ,repair method instruction...");
        final ClassLoader classLoader = loaderClass.getClassLoader();
        DexFile dexFile = rewrite(memoryDexFile, classLoader);

        // MemoryDataStore memoryDataStore = new MemoryDataStore(buf.length);
        File dumpDir = resolveDumpDir(memoryDexFile);


        //call newHashSet to trigger classLoader load classes in thread pool
        TreeSet<? extends ClassDef> classes = Sets.newTreeSet(Sets.filter(dexFile.getClasses(), new Predicate<ClassDef>() {
            //有些class是各种常见api的，全部dump太费事儿了，过滤一遍
            ClassDumpSkipStrategy classDumpSkipStrategy = new ClassDumpSkipStrategy();

            @Override
            public boolean apply(final ClassDef input) {
                return !classDumpSkipStrategy.skip(CommonUtil.descriptorToDot(input.getType()));
            }
        }));

        List<? extends ClassDef> classDefsList = Lists.newArrayList(classes);

        mergeTempFile(dumpDir);
        //先构建已经定义过的class
        final Set<String> internedClass = Sets.newHashSet();

        File[] files = dumpDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return StringUtils.endsWithIgnoreCase(name, ".dextemp");
            }
        });


        //我对产生的class分片dump，这是不得已，主要是因为classdefine的某些特殊顺序，将会导致程序闪退，且没有任何日志。通过分片保存任务，
        //这样下次启动的时候，将不再需要去虚拟机中寻找已经dump出来的class了

        //收集已经成功dump的class
        for (File file : files) {
            collectSuccesClasses(file, internedClass);
        }

        //神坑  DexPool 和DexBuilder，如果是从smali编译，那么需要使用DexBuilder，如果是使用内存中的DexFile对象，那么使用DexPool
        DexPool tempDexPool = new DexPool(Opcodes.forApi(apiLevel()));
        //如果先扫描一遍已经在虚拟机中被定义的class，现行dump，这些class肯定不会出现异常
        for (ClassDef classDef : classDefsList) {
            try {
                if (internedClass.contains(classDef.getType())) {
                    continue;
                }
                if (isClassDefined(classDef.getType(), classLoader)) {
                    Log.e("weijia", "intern class:" + CommonUtil.descriptorToDot(classDef.getType()));
                    internedClass.add(classDef.getType());
                    tempDexPool.internClass(classDef);
                }
            } catch (Exception e) {
                XposedBridge.log(e);
                Log.e("weijia", "error when define class:" + classDef.getType() + " skipped for rebuild it");
            }
        }

        int batch = 1;
        if (internedClass.size() > 0) {
            writeToTempFile(tempDexPool, dumpDir, batch++);
        }

        classDefsList = Lists.newLinkedList(Iterables.filter(classDefsList, new Predicate<ClassDef>() {
            @Override
            public boolean apply(@Nullable ClassDef input) {
                return input != null && !internedClass.contains(input.getType());
            }
        }));

        tempDexPool = new DexPool(Opcodes.forApi(apiLevel()));
        //从这里开始，将会存在去虚拟机定义class的动作，这可能导致虚拟机闪退，有些class define貌似会触发什么bug，不是中断，不是异常，反正日志也没有。。
        int i = 0;
        for (ClassDef classDef : classDefsList) {
            try {
                Log.e("weijia", "rebuild class:" + CommonUtil.descriptorToDot(classDef.getType()));
                if (!makeSureClassValid(classLoader, classDef)) {
                    Log.i("weijia", "error when define class:" + classDef.getType() + " skipped for rebuild it");
                    continue;
                }
                tempDexPool.internClass(classDef);
                if (i++ % 10 == 0) {
                    writeToTempFile(tempDexPool, dumpDir, batch++);
                    tempDexPool = new DexPool(Opcodes.forApi(apiLevel()));
                    //如果超过了500个文件，那么直接进行一次merge
                    if (batch > 500) {
                        mergeTempFile(dumpDir);
                        batch = 1;
                    }
                }

            } catch (Exception e) {
                XposedBridge.log(e);
                Log.e("weijia", "error when define class:" + classDef.getType() + " skipped for rebuild it");
            }
        }
        writeToTempFile(tempDexPool, dumpDir, batch + 1);


        //将所有临时文件，合并为一个单独的dex文件
        //为什么不直接合并在一个单独的dexPool？ 这是因为dexPool只要被写过文件，其内部状态就会改变，不能再写第二次了
        assembleDex(dumpDir);
    }

    private static void assembleDex(File dumpDir) {
        File[] files = dumpDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return StringUtils.endsWithIgnoreCase(name, ".dextemp");
            }
        });
        List<File> fileList = Lists.newArrayList(files);
        if (fileList.size() == 0) {
            return;
        }
        DexPool dexPool = new DexPool(Opcodes.forApi(apiLevel()));
        int i = 0;
        Set<String> internedClasses = new HashSet<>();
        for (File file : fileList) {
            try {
                DexBackedDexFile dexBackedDexFile = DexFileFactory.loadDexFile(file, Opcodes.forApi(apiLevel()));
                Set<? extends DexBackedClassDef> classes = dexBackedDexFile.getClasses();
                for (ClassDef classDef : classes) {
                    if (internedClasses.contains(classDef.getType())) {
                        continue;
                    }
                    Log.e("weijia", "assemble class:" + CommonUtil.descriptorToDot(classDef.getType()));
                    dexPool.internClass(classDef);
                    internedClasses.add(classDef.getType());
                }
            } catch (DexFileFactory.UnsupportedFileTypeException e1) {
                //如果是坏文件，直接删除
                file.delete();
            } catch (Exception e) {
                Log.e("weijia", "error when load dex part temp", e);
            }
        }

        FileDataStore fileDataStore;
        try {
            File targetFile = new File(dumpDir, StringUtils.substringAfterLast(dumpDir.getAbsolutePath(), "/") + "_classes.dex");
            Log.e("weijia", "dump dex ,create dex out put file: " + targetFile.getAbsolutePath());
            if (targetFile.exists() && !targetFile.delete()) {
                XposedBridge.log("failed to clean dex output file" + targetFile.getAbsolutePath());
            }
            fileDataStore = new FileDataStore(targetFile);
            dexPool.writeTo(fileDataStore);
            fileDataStore.close();
            clearTempFile(dumpDir);
            Log.e("weijia", "dex dump finished");
        } catch (IOException e) {
            Log.e("weijia", "can not create dex out file", e);
            throw new RuntimeException(e);
        }
    }

    private static void mergeTempFile(File dumpDir) {
        File[] files = dumpDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return StringUtils.endsWithIgnoreCase(name, ".dextemp");
            }
        });
        List<File> fileList = Lists.newArrayList(files);
        if (fileList.size() <= 1) {
            return;
        }
        Collections.sort(fileList, new Comparator<File>() {
            @Override
            public int compare(File o1, File o2) {
                return Long.valueOf(o2.lastModified()).compareTo(o1.lastModified());
            }
        });
        DexPool dexPool = new DexPool(Opcodes.forApi(apiLevel()));
        int i = 0;
        Set<String> internedClasses = new HashSet<>();
        List<File> canRemoveFile = Lists.newLinkedList();
        for (File file : fileList) {
            try {
                DexBackedDexFile dexBackedDexFile = DexFileFactory.loadDexFile(file, Opcodes.forApi(apiLevel()));
                Set<? extends DexBackedClassDef> classes = dexBackedDexFile.getClasses();
                for (ClassDef classDef : classes) {
                    if (internedClasses.contains(classDef.getType())) {
                        continue;
                    }
                    Log.i("weijia", "merge class:" + CommonUtil.descriptorToDot(classDef.getType()));
                    dexPool.internClass(classDef);
                    internedClasses.add(classDef.getType());
                }
                canRemoveFile.add(file);

                if (i++ % 50 == 0) {
                    FileDataStore fileDataStore = new FileDataStore(new File(dumpDir, UUID.randomUUID().toString() + "_" + i + ".dextemp"));
                    dexPool.writeTo(fileDataStore);
                    fileDataStore.close();
                    for (File removeFile : canRemoveFile) {
                        removeFile.delete();
                    }
                    canRemoveFile.clear();
                    dexPool = new DexPool(Opcodes.forApi(apiLevel()));
                }
            } catch (DexFileFactory.UnsupportedFileTypeException e1) {
                //如果是坏文件，直接删除
                file.delete();
            } catch (Exception e) {
                Log.e("weijia", "error when load dex part temp", e);
            }
        }

        try {
            FileDataStore fileDataStore = new FileDataStore(new File(dumpDir, UUID.randomUUID().toString() + "_" + i + ".dextemp"));
            dexPool.writeTo(fileDataStore);
            fileDataStore.close();
            for (File removeFile : canRemoveFile) {
                removeFile.delete();
            }
            canRemoveFile.clear();
        } catch (Exception e) {
            Log.e("weijia", "error when load dex part temp", e);
        }
    }

    private static void clearTempFile(File dumpDir) {
        for (File file : dumpDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return StringUtils.endsWithIgnoreCase(name, ".dextemp");
            }
        })) {
            file.delete();
        }
    }


    private static void writeToTempFile(DexPool dexPool, File dir, int batch) {
        File file = new File(dir, "part_" + UUID.randomUUID().toString() + "_" + batch + ".dextemp");
        try {
            FileDataStore fileDataStore = new FileDataStore(file);
            dexPool.writeTo(fileDataStore);
            fileDataStore.close();
        } catch (Exception e) {
            Log.e("weijia", "error when write dex part temp", e);
        }
    }

    private static void collectSuccesClasses(File file, Set<String> internedClasses) {
        try {
            DexBackedDexFile dexBackedDexFile = DexFileFactory.loadDexFile(file, Opcodes.forApi(apiLevel()));
            Set<? extends DexBackedClassDef> classes = dexBackedDexFile.getClasses();
            for (ClassDef classDef : classes) {
                if (internedClasses.contains(classDef.getType())) {
                    continue;
                }
                internedClasses.add(classDef.getType());
            }
        } catch (DexFileFactory.UnsupportedFileTypeException e1) {
            //如果是坏文件，直接删除
            file.delete();
        } catch (Exception e) {
            Log.e("weijia", "error when load dex part temp", e);
        }
    }


    /**
     * 将指定loader的smali全部dump到硬盘，请异步执行该函数
     *
     * @param loader loader
     */
    public static void dissembleAllDex(Object loader) {
        Class loaderClass = resolveLoaderClass(loader);
        if (isDumped(loaderClass.getClassLoader())) {
            XposedBridge.log("dump dex ,this dex always dumped,skip it");
            return;
        }
        DexBackedDexFile memoryMethodDexFile = createMemoryDexFile(loaderClass);
        File dumpDir = resolveDumpDir(memoryMethodDexFile);
        DexFile reWritedDexFile = rewrite(memoryMethodDexFile, loaderClass.getClassLoader());
        XposedBridge.log("脱壳目录:" + dumpDir.getAbsolutePath());
        int jobs = Runtime.getRuntime().availableProcessors();
        if (jobs > 6) {
            jobs = 6;
        }
        if (memoryMethodDexFile instanceof DexBackedOdexFile) {
            baksmaliOptions.inlineResolver = InlineMethodResolver
                    .createInlineMethodResolver(((DexBackedOdexFile) memoryMethodDexFile).getOdexVersion());
        }
        Log.i("weijia", "开始进行脱壳");
        if (Baksmali.disassembleDexFile(reWritedDexFile, dumpDir, jobs, baksmaliOptions)) {
            Log.i("weijia", "脱壳完成，但是存在错误");
        } else {
            Log.i("weijia", "脱壳成功，请在" + dumpDir + "中查看smali文件");
        }
        Toast.makeText(SharedObject.context, "脱壳完成，请在" + dumpDir + "中查看smali文件", Toast.LENGTH_LONG).show();
    }


    private static File resolveDumpDir(DexBackedDexFile memoryMethodDexFile) {
        //resolve signature
        DexReader signatureReader = memoryMethodDexFile.readerAt(0x0c);
        int[] signName = new int[]{23, 94, 56, 238, 94};
        for (int i = 0; i < 20; i++) {
            signName[i % signName.length] ^= signatureReader.readByte();
        }
        StringBuilder stringBuilder = new StringBuilder(signName.length * 2);
        for (int by : signName) {
            stringBuilder.append(hexMap[(by & 0xff) >> 4]);
            stringBuilder.append(hexMap[by & 0x0f]);
        }
        File dumpSmaliDir = new File(SharedObject.context.getFilesDir(), "dumpSmali");
        File targetDir = new File(dumpSmaliDir, stringBuilder.toString());
        if (!targetDir.exists()) {
            if (!targetDir.mkdirs()) {
                throw new IllegalStateException("can not create smali output directory for path: " + targetDir.getAbsolutePath());
            }
        }

        if (targetDir.isFile()) {
            throw new IllegalStateException("target smali dump path : " + targetDir.getAbsolutePath() + " is not a directory");
        }
        return targetDir;
    }

    public static String disassembleTargetClass(Object loader, DexFile memoryMethodDexFile) {
        Class loaderClass = resolveLoaderClass(loader);
        String className = loaderClass.getName();
        ClassDef targetClass = null;
        for (ClassDef dexBackedClassDef : memoryMethodDexFile.getClasses()) {
            if (StringUtils.equals(CommonUtil.descriptorToDot(dexBackedClassDef.getType()), className)) {
                targetClass = dexBackedClassDef;
                break;
            }
        }
        if (targetClass == null) {
            throw new IllegalStateException("can not find class definition for class: " + className);
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(512);
        BufferedWriter bufWriter = new BufferedWriter(
                new OutputStreamWriter(byteArrayOutputStream,
                        Charsets.UTF_8));

        IndentingWriter writer = new IndentingWriter(bufWriter);
        try {
            new ClassDefinition(baksmaliOptions, targetClass).writeTo(writer);
            writer.flush();
        } catch (IOException e) {
            //内存的流，不会发生io异常，直接catch掉
            throw new RuntimeException(e);
        }
        return byteArrayOutputStream.toString();
    }

    /**
     * dex映射虚拟机内存，虚拟机内存mmap映射文件，不会真正发生数据拷贝
     *
     * @param loader loader，可以是class对象，也可以是任何一个变量。如果是class对象，则获取class内部的dex，如果是普通对象，则获取class，然后寻找dex
     * @return 反编译出来的smali代码
     */
    public static String disassembleTargetClass(Object loader) {
        //loader.getClass()
        Class<?> loaderClass = resolveLoaderClass(loader);
        return disassembleTargetClass(loader, rewrite(createMemoryDexFile(loaderClass), loaderClass.getClassLoader()));
    }

    private static BaksmaliOptions baksmaliOptions = configOption();


    private static BaksmaliOptions configOption() {
        BaksmaliOptions options = new BaksmaliOptions();

        // options
        options.allowOdex = true;
        options.deodex = false;
        // options.deodex = false;
        options.implicitReferences = false;
        options.parameterRegisters = true;
        options.localsDirective = true;
        options.sequentialLabels = true;
        options.debugInfo = false;
        options.codeOffsets = false;
        options.accessorComments = false;
        //TODO
        options.registerInfo = 0;
        options.inlineResolver = null;
        return options;
    }

    /**
     * 可以给jni调用的method Descriptor 构造，没有define class，没有method name，仅仅包含参数类型列表和返回类型列表
     *
     * @param methodReference 一个smali的method模型
     * @return 方法描述，可以借此寻找到一个method id
     */
    private static String getMethodDescriptor(MethodReference methodReference) {
        StringBuilder sb = new StringBuilder();
        sb.append('(');
        for (CharSequence paramType : methodReference.getParameterTypes()) {
            sb.append(paramType);
        }
        sb.append(')');
        sb.append(methodReference.getReturnType());
        return sb.toString();
    }


    public static native int apiLevel();

    //--------以下为java和虚拟机中的method对象通信的接口----------------//


    public static native ByteBuffer methodDataWithDescriptor(String methodDescriptor, String methodName, Class<?> searchClass);

    public static native int getMethodAccessFlagsWithDescriptor(String methodDescriptor, String methodName, Class<?> searchClass);
}