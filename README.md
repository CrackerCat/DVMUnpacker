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

art脱壳机

## 特点
1. 理论上兼容各种art机型，如Android5-android10，小米、华为、三星
2. 不需要刷机或者编译系统，只要能注入代码就可以脱壳。可以使用virtualXposed或者太极之类的免root框架
3. 脱壳粒度在方法粒度，也即大部分方法抽取，方法执行后解密等case都是可以脱壳（不支持VMP和方法执行后抹除场景）
4. 支持32和64位手机
5. 支持多classloader，动态加载类型dex，加载行为通过javaAPI控制。灵活方便

## 原理

### 定位method invoke方法
在art中有Method->Invoke方法导出，通过符号查找即可。
```
#define ART_METHOD_INVOKE_SYM "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"

void *handle = getSymCompat(
            art_lib_path, ART_METHOD_INVOKE_SYM);
    if (handle == nullptr) {
        UNPACK_LOGW("can not find symbol: %s ratel unpack will not running", ART_METHOD_INVOKE_SYM);
        return;
    }
```

### invoke方法hook
也不难，选择一个比较好的inlinehook框架就可以，我现在选择的是
- 32位： https://github.com/ele7enxxh/Android-Inline-Hook
- 64位：https://github.com/Rprop/And64InlineHook

有大佬的代码抄，还是很舒服的

### ArtMethod -> DexFile -> Dex
这一步有点麻烦，在dumpMethod的时候，需要知道这个Method在那个Dex上面，如果是编译系统方式，有一大堆API可以调用。
但是如果通过hook来操作的话，大部分API都被inline或者粉碎了。

ArtMethod有一个函数，``GetDexFile``，然后这个函数被inline了，所以直接通过getSymCompat也拿不到函数地址。不过我试了下，
AsLody的whale框架还是又点儿牛逼，whale框架可以获取到这个符号： https://github.com/asLody/whale/blob/master/whale/src/platform/linux/elf_image.h#L140

```
 auto range = whale::FindExecuteMemoryRange(art_lib_path);
    if (range->IsValid()) {
        whale::ElfImage *image = new whale::ElfImage();
        if (!image->Open(range->path_, range->base_)) {
            delete image;
        } else {
            void *getDexFileHandle = image->FindSymbol<void *>("_ZN3art9ArtMethod10GetDexFileEv");
            UNPACK_LOGI("getDexFileHandle: %p", getDexFileHandle);
            this->getDexFile_handle = (void *(*)(art::mirror::ArtMethod *)) (getDexFileHandle);
        }
    }

```
不要问，用它就是了

### 指令定位
在方法执行的时候，找到了Dex，也知道执行的是那个ArtMethod对象，这个时候如果再找到ArtMethod的CodeItem，基本脱壳功能就能搞了。
指令定位这里，主要依靠ArtMethod的字段计算，包括 dex_code_item_offset_和 dex_method_index_，但是由于Android不同版本
碎片化问题，我们不能直接写死偏移。这个时候就可以抄sandhok了： https://github.com/ganyao114/SandHook

核心原理：手动构造两个方法，在虚拟机层面转换成ArtMethod，然后两个Artmethod的地址差值就是ArtMethod结构体的大小。
再然后在结构体中搜索accessFlag等已知属性的地址，找到一些航标偏移。再然后根据航标计算我们关心的成员的位置。

```
    class CastDexMethodIndex : public IMember<art::mirror::ArtMethod, uint32_t> {
    protected:
        Size calOffset(JNIEnv *jniEnv, art::mirror::ArtMethod *p) override {
            if (SDK_INT >= ANDROID_P) {
                return CastArtMethod::accessFlag->getOffset()
                       + CastArtMethod::accessFlag->size()
                       + sizeof(uint32_t);
            }
            int offset = 0;
            jint index = getIntFromJava(jniEnv, "com/virjar/artunpacker/SandHookMethodResolver",
                                        "dexMethodIndex");
            if (index != 0) {
                offset = findOffset(p, getParentSize(), 2, static_cast<uint32_t>(index));
                if (offset >= 0) {
                    return static_cast<Size>(offset);
                }
            }
            return getParentSize() + 1;
        }
    };
```

最后，计算CodeItem的数据，dump到文件，齐活儿：
```

void DexFileHolder::dumpMethod(art::mirror::ArtMethod *artMethod) {
    if (artMethod->isAbstract()) {
        return;
    }
    if (artMethod->isNative()) {
        return;
    }


    // Offset to the CodeItem.
    uint32_t dex_code_item_offset_ = artMethod->getDexCodeItemIndex();
    // Index into method_ids of the dex file associated with this method.
    uint32_t dex_method_index_ = artMethod->getDexMethodIndex();


    auto *codeItem = (CodeItem *) (this->begin_ + dex_code_item_offset_);

    auto inter = this->dumped_method.find(dex_method_index_);
    if (inter != this->dumped_method.end()) {
        //dumped already
        return;
    }
    std::string method_sign = UnpackerInstance.prettyMethod(artMethod);
    UNPACK_LOGI("dump method: %s  dex_code_item_offset_: %u dex_method_index_: %u",
                method_sign.c_str(), dex_code_item_offset_, dex_method_index_);
    this->dumped_method.insert(std::pair<uint32_t, bool>(dex_method_index_, true));

    auto *item = (uint8_t *) codeItem;
    int code_item_len;
    if (codeItem->tries_size_) {
        const u1 *handler_data = reinterpret_cast<const uint8_t *>(GetTryItems(*codeItem,
                                                                               codeItem->tries_size_));
        uint8_t *tail = codeitem_end(&handler_data);
        code_item_len = (int) (tail - item);
    } else {
        //正确的DexCode的大小
        code_item_len = 16 + codeItem->ins_size_ * 2;
    }

    if (code_item_len == 0) {
        //空函数body
        return;
    }

    char method_dump_file[PATH_MAX] = {'\0'};
    sprintf(method_dump_file, "%s%d_%d.bin", this->method_dump_dirs.c_str(), dex_method_index_,
            code_item_len);

    if (access(method_dump_file, F_OK) == 0) {
        // 已经写过了
        return;
    }
    UNPACK_LOGI("dump method into file:%s", method_dump_file);
    std::ofstream out_method_file;
    out_method_file.open(method_dump_file, std::ios::out | std::ios::binary);
    if (!out_method_file.is_open()) {
        UNPACK_LOGE("can not open file: %s", method_dump_file);
        return;
    }
    out_method_file.write((const char *) (item), code_item_len);
    out_method_file.flush();
    out_method_file.close();
}
```

## 使用：
直接调用javaAPI： com.virjar.artunpacker.ArtUnPacker.enableUnpackComponent
传递一个文件下路径，然后脱壳机会把方法指令数据和dex数据dump到这个文件夹下面。

## 所以Xposed遗民也是可以用MethodTrace功能的emmmm

github地址：https://github.com/virjar/DVMUnpacker/tree/master/artunpacker/src/main

对了，脱壳机是内部代码剥离出来的，自己跑起来没问题，github项目暂时没有实际跑过。有bug的话自己改改。
要么就给我钱，捐赠就干活儿。



