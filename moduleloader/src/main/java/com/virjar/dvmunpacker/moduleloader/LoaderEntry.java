package com.virjar.dvmunpacker.moduleloader;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Process;
import android.util.Log;

import com.virjar.dvmunpacker.commons.Constants;

import dalvik.system.PathClassLoader;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XCallback;

public class LoaderEntry implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    private static volatile boolean attached = false;

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.isFirstApplication) {
            return;
        }

        if ("android".equalsIgnoreCase(lpparam.processName)) {
            return;
        }
        if (Process.myUid() < Process.FIRST_APPLICATION_UID) {
            //这个项目单纯定义为脱壳机，所以系统应用没有脱壳的概念
            return;
        }

        XC_MethodHook contextCollectHook = new XC_MethodHook(XCallback.PRIORITY_HIGHEST * 2) {

            //由于集成了脱壳功能，所以必须选择before了
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                Context context = (Context) param.args[0];
                doLoad(context, lpparam);
            }

        };


        Class<?> tencentStubShell = findClassIfExists("com.tencent.StubShell.TxAppEntry", lpparam.classLoader);
        if (tencentStubShell != null) {
            //com.tencent.StubShell.TxAppEntry#load
            XposedHelpers.findAndHookMethod(tencentStubShell, "load", Context.class, contextCollectHook);
        } else {
            XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, contextCollectHook);
        }

    }

    //低版本 xposed不支持这个函数，所以迁移过来实现兼容
    private static Class<?> findClassIfExists(String className, ClassLoader classLoader) {
        try {
            return XposedHelpers.findClass(className, classLoader);
        } catch (XposedHelpers.ClassNotFoundError e) {
            return null;
        }
    }


    private static void doLoad(Context context, XC_LoadPackage.LoadPackageParam lpparam) {
        if (attached) {
            return;
        }
        attached = true;
        lpparam.classLoader = context.getClassLoader();
        ApplicationInfo applicationInfo;
        try {
            applicationInfo = context.getPackageManager().getApplicationInfo("com.virjar.dvmunpacker.unpacker", 0);
        } catch (PackageManager.NameNotFoundException e) {
            Log.w(Constants.TAG, "the unPacker not installed");
            return;
        }

        PathClassLoader pathClassLoader = new PathClassLoader(applicationInfo.sourceDir, applicationInfo.nativeLibraryDir, LoaderEntry.class.getClassLoader());

        Class<?> unPackClass;
        try {
            unPackClass = pathClassLoader.loadClass(Constants.LOADER_UNPACK_ENTRY_CLASS);
        } catch (ClassNotFoundException e) {
            Log.e(Constants.TAG, "can not find unpack class:", e);
            return;
        }
        //中间做一次跳转，可以实现
        XposedHelpers.callStaticMethod(unPackClass, "process", context, lpparam);
    }


    private static final int DEBUG_ENABLE_DEBUGGER = 0x1;
    private XC_MethodHook debugAppsHook = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param)
                throws Throwable {
            XposedBridge.log("-- beforeHookedMethod :" + param.args[1]);
            int id = 5;
            int flags = (Integer) param.args[id];
            if ((flags & DEBUG_ENABLE_DEBUGGER) == 0) {
                flags |= DEBUG_ENABLE_DEBUGGER;
            }
            param.args[id] = flags;
        }
    };

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        //https://github.com/deskid/XDebug 让所有进程处于可以被调试的状态
        XposedBridge.hookAllMethods(Process.class, "start", debugAppsHook);
    }
}
