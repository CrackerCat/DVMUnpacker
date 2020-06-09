## DVMUnpacker
这是一个脱壳机，思路改造自DexHunter，为Xposed模块工程，目前只能在Dalvik上面执行，也就是说只支持android4.4以及以下

由于基于Xposed，天生存在一些问题。比如插件需要重启手机、小米手机经常出现apk安装路径不正确导致插件不能加载。

所以DVMUnPacker有两个项目，分别为:moduleloader和unpacker。

moduleloader是一个标准的xposed插件，负责加载unpacker，以提供不重启手机加载unpacker的功能。
unpacker真正的实现脱壳功能


脱壳机代码参考: com.virjar.dvmunpacker.unpacker.apps.HaiDiLaoHook
为了提高效率，不再提供代码扫描功能，脱壳业务逻辑需要在： com.virjar.dvmunpacker.unpacker.UnPackerEntry.setupProcessors 手工配置


## 优点

可以在不用刷机的情况下，拖掉一些指令抽取类型的壳。如果在va之类的容器中运行，甚至可以免root实现脱壳。目前市面上所有针对指令抽取类型的开源方案应该都是要编译系统的。

## 缺点

现在流行frida了，作为我们这种还生活在xposed环境下，快半截身体入土的老人emmm，可能再等几年xposed都找不到道友了吧。

只支持Dalvik，现在很多app都已经不支持Dalvik了。不过如果不是现在app大部分都是art，我估计也不会把这个放出来。

不支持指令执行后抹除的场景。不过这种场景貌似也不多？？

#### 捐赠
如果你觉得作者辛苦了，可以的话请我喝杯咖啡
![alipay](deploy/reward.jpg)