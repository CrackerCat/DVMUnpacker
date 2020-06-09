package com.virjar.dvmunpacker.unpacker;

import android.content.Context;
import android.util.Log;

import com.virjar.dvmunpacker.commons.Constants;
import com.virjar.dvmunpacker.unpacker.apps.HaiDiLaoHook;

import java.util.concurrent.ConcurrentHashMap;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

@SuppressWarnings("unused")
public class UnPackerEntry {

    private static ConcurrentHashMap<String, PackageProcessor> processorConcurrentHashMap = new ConcurrentHashMap<>();

    public static void process(Context context, XC_LoadPackage.LoadPackageParam lpparam) {

        SharedObject.context = context;
        SharedObject.lpparam = lpparam;


        setupProcessors();

        PackageProcessor packageProcessor = processorConcurrentHashMap.get(lpparam.packageName);
        if (packageProcessor == null) {
            return;
        }
        Log.i(Constants.TAG, "execute processor: " + packageProcessor.getClass().getName() + " for app: " + lpparam.processName);
        packageProcessor.process();

    }

    public interface PackageProcessor {
        void process();
    }

    private static void setupProcessors() {
        //DO setup here
        processorConcurrentHashMap.put("com.haidilao", new HaiDiLaoHook());
    }
}
