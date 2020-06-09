package com.virjar.dvmunpacker.unpacker;

import android.annotation.SuppressLint;
import android.content.Context;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class SharedObject {
    @SuppressLint("StaticFieldLeak")
    public static Context context;
    public static XC_LoadPackage.LoadPackageParam lpparam;
}
