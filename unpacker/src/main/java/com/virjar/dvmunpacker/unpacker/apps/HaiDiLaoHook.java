package com.virjar.dvmunpacker.unpacker.apps;

import android.app.Activity;
import android.util.Log;

import com.virjar.dvmunpacker.unpacker.UnPackerEntry;
import com.virjar.dvmunpacker.unpacker.unpack.Dumper;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

public class HaiDiLaoHook implements UnPackerEntry.PackageProcessor {
    @Override
    public void process() {

        XposedHelpers.findAndHookMethod(Activity.class, "onResume", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Log.i("weijia", "begin of unpack: " + param.thisObject.getClass().getName());
                        if ("com.haidilao.hailehui.biz.impl.activity.SecondActivity".equals(param.thisObject.getClass().getName())) {
                            Dumper.dumpDexWithoutTempFile(param.thisObject);
                        }
                    }
                }
        );

    }
}
