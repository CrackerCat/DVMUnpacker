package com.virjar.dvmunpacker.unpacker.unpack;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import java.util.ArrayList;
import java.util.Map;

/**
 * Created by virjar on 2018/3/26.<br>快速搜搜package
 */

public class ClassDumpSkipStrategy {
    private static class PackageSearchNode {
        private static final Splitter dotSplitter = Splitter.on(".").omitEmptyStrings();

        private Map<String, PackageSearchNode> children = Maps.newHashMap();

        public void addToTree(ArrayList<String> packageSplitItems, int index) {
            if (index > packageSplitItems.size() - 1) {
                children.clear();
                return;
            }
            String node = packageSplitItems.get(index);
            PackageSearchNode packageSearchNode = children.get(node);
            if (packageSearchNode == null) {
                packageSearchNode = new PackageSearchNode();
                children.put(node, packageSearchNode);
            }
            packageSearchNode.addToTree(packageSplitItems, index + 1);
        }

        public void addToTree(String packageName) {
            addToTree(Lists.newArrayList(dotSplitter.split(packageName)), 0);
        }

        public boolean isSubPackage(String packageName) {
            return isSubPackage(Lists.newArrayList(dotSplitter.split(packageName)), 0);
        }

        public boolean isSubPackage(ArrayList<String> packageSplitItems, int index) {
            if (children.size() == 0) {
                return true;
            }
            if (index > packageSplitItems.size() - 1) {
                return false;
            }

            String node = packageSplitItems.get(index);
            return children.containsKey(node) && children.get(node).isSubPackage(packageSplitItems, index + 1);
        }
    }

    private PackageSearchNode root = new PackageSearchNode();

    public boolean skip(String packageName) {
        return root.isSubPackage(packageName);
    }

    protected void addInitSkipPackage() {
        root.addToTree("com.android");
        root.addToTree("android");
        root.addToTree("java.lang");
        root.addToTree("com.alibaba");
        root.addToTree("com.alipay");
        root.addToTree("com.baidu");
        root.addToTree("com.tencent");
        root.addToTree("com.google");
        root.addToTree("com.networkbench");
        root.addToTree("com.sina.weibo");
        root.addToTree("com.taobao");
        root.addToTree("com.tendcloud");
        root.addToTree("com.umeng.message");
        root.addToTree("org.android");
        root.addToTree("org.aspectj");
        root.addToTree("org.java_websocket");
        root.addToTree("com.amap");

        //root.addToTree("com.neusoft.network");
        root.addToTree("com.air.sz.ui.widget.ViewExchangePickervug");
        root.addToTree("anet");
        root.addToTree("com.aograph.agent");
        root.addToTree("retrofit2.b");

    }

    public void addSkipPackage(String packageName) {
        root.addToTree(packageName);
    }

    public ClassDumpSkipStrategy() {
        addInitSkipPackage();
    }
}
