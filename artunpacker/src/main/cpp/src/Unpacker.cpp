//
// Created by 邓维佳 on 2020/8/28.
//

#include "Unpacker.h"

#include <utility>

#include <fstream>
#include <ostream>
#include <zconf.h>
#include <jni.h>

#include <cast.h>
#include <sys/system_properties.h>
#include "inlinehook_32/inlineHook.h"
#include "dex_ratel.h"
#include "elf_image.h"
#include "process_map.h"
#include "dlfcn_nougat.h"
#include "native_api.h"



//ArtMethod.Invoke()
#define ART_METHOD_INVOKE_SYM "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"

#define AER_METHOD_PRETTY_METHOD "_ZN3art9ArtMethod12PrettyMethodEb"


extern const char *art_lib_path;
extern int SDK_INT;
Unpacker UnpackerInstance;

void (*artMethod_Invoke_Origin)(
        art::mirror::ArtMethod *thiz,
        void *thread_self, uint32_t *args, uint32_t args_size, JValue *result,
        const char *shorty) = nullptr;

void artMethod_Invoke_fake(
        art::mirror::ArtMethod *art_method,
        void *thread_self, uint32_t *args, uint32_t args_size, JValue *result,
        const char *shorty) {
    artMethod_Invoke_Origin(art_method, thread_self, args, args_size, result, shorty);
    UnpackerInstance.handleMethodDump(art_method);
}

void Unpacker::init(std::string dump_work_dir) {
    this->dumpWorkDir = std::move(dump_work_dir);

    // resolve method invoke
    void *handle = getSymCompat(
            art_lib_path, ART_METHOD_INVOKE_SYM);
    if (handle == nullptr) {
        UNPACK_LOGW("can not find symbol: %s ratel unpack will not running", ART_METHOD_INVOKE_SYM);
        return;
    }

    void *handle_prettyMethod = getSymCompat(art_lib_path, AER_METHOD_PRETTY_METHOD);
    if (handle_prettyMethod == nullptr) {
        UNPACK_LOGW("can not find symbol: %s ratel unpack will not running",
                    handle_prettyMethod);
        return;
    }

    this->prettyMethod_handler = (std::string(*)(art::mirror::ArtMethod *artMethod,
                                                 bool
                                                 with_signature)) (handle_prettyMethod);

#if defined(__aarch64__)
    A64HookFunction(handle, (void *) artMethod_Invoke_fake, (void **) &artMethod_Invoke_Origin)
#else
    if (registerInlineHook((uint32_t) handle, (uint32_t) artMethod_Invoke_fake,
                           (uint32_t **) &artMethod_Invoke_Origin) != ELE7EN_OK) {
        UNPACK_LOGE("register hook failed");
        return;
    }

    if (inlineHook((uint32_t) handle) != ELE7EN_OK) {
        UNPACK_LOGE("register hook failed");
        return;
    }
#endif // defined(__aarch64__)
    UNPACK_LOGI("ratel unpack init finished!");


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

    this->open = true;
}

static bool check_dex_magic(const uint8_t *dex_data) {
    if (dex_data == nullptr) {
        return false;
    }

    if ((unsigned long) dex_data % (sizeof(uint8_t *)) != 0) {
        //不是指针
        return false;
    }

    // check if this is dex file "dex\n035\0"
    static uint8_t magic[] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
    for (int i = 0; i < sizeof(magic); i++) {
        if (magic[i] != dex_data[i]) {
            return false;
        }
    }
    return true;
}

void Unpacker::handleMethodDump(art::mirror::ArtMethod *artMethod) {
    if (!this->open) {
        return;
    }

    //UNPACK_LOGI("dump method: %s", method_sign.c_str());
    // 当方法执行完成之后，执行dump
    void *dexFile = getDexFile(artMethod);
    if (dexFile == nullptr) {
        UNPACK_LOGW("can not get dexFile from artMethod");
        return;
    }

    DexFileHolder *dexFileHolder = this->get_or_create_dex_image(dexFile);
    if (dexFileHolder->valid()) {
        dexFileHolder->dumpMethod(artMethod);
    } else {
        // UNPACK_LOGW("can not locate dex image for method:%s", method_sign.c_str());
    }
}

DexFileHolder *Unpacker::get_or_create_dex_image(void *dex_file_handle) {
    auto iter = this->dex_file_holder_map.find(
            dex_file_handle);
    if (iter != this->dex_file_holder_map.end()) {
        return iter->second;
    }
    //std::string method_sign = prettyMethod(artMethod);
    UNPACK_LOGI("dump dexFile: %p", dex_file_handle);
    // 扫描 dexFile对象
    // 当android版本小于9.0的时候，第一个字段为dex开始，第二个字段为dex大小
    // 当Android版本大于等于9.0的时候，前面加一组VDex映射，之后是标准dex开始和标准dex大小
    const uint8_t *begin_;
    size_t size_;
    //const Header *header_;
    if (SDK_INT >= ANDROID_P) {
        auto *dexFileP = static_cast<DexFileP *>(dex_file_handle);
        // The base address of the memory mapping.
        begin_ = dexFileP->data_begin_;
        // The size of the underlying memory allocation in bytes.
        size_ = dexFileP->data_size_;

    } else {
        auto *dexFileO = (DexFileO *) (dex_file_handle);
        // The base address of the memory mapping.
        begin_ = dexFileO->begin_;

        // The size of the underlying memory allocation in bytes.
        size_ = dexFileO->size_;
    }

    auto *dexFileHolder = new DexFileHolder(this->dumpWorkDir);
    this->dex_file_holder_map.insert(
            std::pair<void *, DexFileHolder *>(dex_file_handle, dexFileHolder)
    );

    if (check_dex_magic(begin_)) {
        // 当前位置
        dexFileHolder->size_ = size_;
        dexFileHolder->begin_ = begin_;
        dumpRawDex(dexFileHolder);
        return dexFileHolder;
    }
    return dexFileHolder;
}

void Unpacker::dumpRawDex(DexFileHolder *dexFileHolder) {
    auto *header = (Header *) dexFileHolder->begin_;
    uint8_t *signature_ = header->signature_;

    char sig_chars[kSha1DigestSize * 2 + 1];

    static char char_map[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                              'E', 'F'};

    for (unsigned int i = 0; i < kSha1DigestSize; i++) {
        sig_chars[i * 2] = char_map[(signature_[i] >> 4u) & 0x0fu];
        sig_chars[i * 2 + 1] = char_map[signature_[i] & 0x0fu];
    }
    sig_chars[kSha1DigestSize * 2] = '\0';


    char dex_path[PATH_MAX];
    sprintf(dex_path, "%s%s_method_dump/", this->dumpWorkDir.c_str(), sig_chars);
    dexFileHolder->method_dump_dirs = std::string(dex_path);
    if (access(dex_path, F_OK) != 0) {
        // 创建文件夹
        mkdir(dex_path, S_IRUSR + S_IWUSR + S_IXUSR);
    }

    sprintf(dex_path, "%s%s.dex", this->dumpWorkDir.c_str(), sig_chars);
    UNPACK_LOGI("dump dex filed into:%s", dex_path);
    if (access(dex_path, F_OK) == 0) {
        // exist
        //UNPACK_LOGE("can not write file:%s", dex_path);
        return;
    }
    std::ofstream out_dex_file;
    out_dex_file.open(dex_path, std::ios::out | std::ios::binary);

    out_dex_file.write(reinterpret_cast<const char *>(dexFileHolder->begin_), dexFileHolder->size_);
    out_dex_file.close();
}

void *Unpacker::getDexFile(art::mirror::ArtMethod *pMethod) {
    return this->getDexFile_handle(pMethod);
}

DexFileHolder::DexFileHolder(std::string dumpWorkDir) : dumpWorkDir(std::move(dumpWorkDir)) {}


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


extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_artunpacker_ArtUnPacker_enableUnpackComponent(JNIEnv *env, jclass clazz,
                                                              jstring dump_dir) {
    const char *_c_str = env->GetStringUTFChars(dump_dir, nullptr);
    UnpackerInstance.init(std::string(_c_str));
    env->ReleaseStringUTFChars(dump_dir, _c_str);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *_vm, void *) {
    JNIEnv *env;
    _vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);

    char sdk[PROP_VALUE_MAX];
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);

    // 一个artmethod转换函数，CastArtMethod初始化的时候会使用到
    initHideApi();
    //计算一些artMethod的属性偏移，主要包括 accessFlag、MethodIndex、dexCodeItemIndex
    // 这些偏移在dump指令的时候需要被使用到
    SandHook::CastArtMethod::init(env);


    return JNI_VERSION_1_6;
}
