//
// Created by 邓维佳 on 2018/3/14.
//

extern "C" {
#include "inlinehook/inlineHook.h"
}

#include <sys/system_properties.h>
#include <fcntl.h>
#include <unistd.h>
#include "DvmFunctionTable.h"
#include "inlinehook/dlopen.h"
#include "init.h"


#include "dexheader.h"

//这里定义全局变量
struct DvmFunctionTables dvmFunctionTables;


void *defaultDvmFunctionHandler(...) {
    //我们只是mock语法错误，不是所有的函数都会处理他
    __android_log_print(ANDROID_LOG_ERROR, TAG, "the function hook not implemented");
    return NULL;
}


void initDvmFunctionItem(const char *functionName, void **functionStoreAddr, void *libVMhandle) {
    void *functionAddress = findFunction(functionName, libVMhandle);
    if (functionAddress == NULL) {
        functionAddress = (void *) defaultDvmFunctionHandler;
    }
    (*functionStoreAddr) = functionAddress;
}

/**
 * 函数名称表根据4.4的Android版本设置的，不同Android版本映射可能存在差异，可以直接用ida查看维护
 */
void initDvmFunctionTables() {
    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    if (libVMhandle == NULL) {
        return;
    }

    initDvmFunctionItem("_Z20dvmDecodeIndirectRefP6ThreadP8_jobject",
                        (void **) (&dvmFunctionTables.dvmDecodeIndirectRef), libVMhandle);
    initDvmFunctionItem("_Z13dvmThreadSelfv", (void **) (&dvmFunctionTables.dvmThreadSelf),
                        libVMhandle);
    //这一句代码兼容性不好
    initDvmFunctionItem("sub_4E110", (void **) (&dvmFunctionTables.RegisterNatives),
                        libVMhandle);
    initDvmFunctionItem("_Z14dvmLookupClassPKcP6Objectb",
                        (void **) (&dvmFunctionTables.dvmLookupClass), libVMhandle);

    dlclose(libVMhandle);
}


void *findFunction(char const *functionName, void *libVMhandle) {
    if (libVMhandle == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Error: unable to find the SO : libdvm.so");
        return NULL;
    }
    return dlsym(libVMhandle, functionName);
}


int apiLevel() {
    char version[10];
    __system_property_get("ro.build.version.sdk", version);
    __android_log_print(ANDROID_LOG_INFO, TAG, "api level %s", version);
    int sdk = atoi(version);
    return sdk;
}

void getProcessName(int pid, char *name, int len) {
    int fp = open("/proc/self/cmdline", O_RDONLY);
    memset(name, 0, len);
    read(fp, name, len);
    close(fp);
}

static char charMap[16];
bool hasCharMapInit = false;

void initCharMap() {
    for (int i = 0; i <= 9; i++) {
        charMap[i] = (char) (i + '0');
    }
    for (int i = 10; i < 16; i++) {
        charMap[i] = (char) (i - 10 + 'A');
    }
    hasCharMapInit = true;
}

void toHex(char *destination, const char *source, int sourceLength) {
    //memset(destination, sourceLength * 2, 0);
    if (!hasCharMapInit) {
        initCharMap();
    }
    for (int i = 0; i < sourceLength; i++) {
        destination[i * 2] = charMap[(source[i] >> 4) & 0xff];
        destination[i * 2 + 1] = charMap[source[i] & 0xff];
    }
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_virjar_dvmunpacker_unpacker_unpack_Dumper_apiLevel(JNIEnv *env, jclass instance) {
    return apiLevel();
}


JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    initDvmFunctionTables();

    JNIEnv *jniEnv;
    vm->GetEnv((void **) &jniEnv, JNI_VERSION_1_6);
    return JNI_VERSION_1_6;
}

jobject createArrayList(JNIEnv *jniEnv) {
    jclass arrayList_class = jniEnv->FindClass("java/util/ArrayList");//获得ArrayList类引用
    jmethodID arrayList_construct = jniEnv->GetMethodID(arrayList_class, "<init>",
                                                        "()V"); //获得得构造函数Id
    return jniEnv->NewObject(arrayList_class, arrayList_construct);
}

jboolean addToArrayList(JNIEnv *jniEnv, jobject arrayList, jobject element) {
    jmethodID list_add = jniEnv->GetMethodID(jniEnv->GetObjectClass(arrayList), "add",
                                             "(Ljava/lang/Object;)Z");
    return jniEnv->CallBooleanMethod(arrayList, list_add, element);
}

void threwIllegalStateException(JNIEnv *jniEnv, const char *message) {
    jniEnv->ExceptionDescribe();
    jniEnv->ExceptionClear();
    jclass illegalStateExceptionClass = jniEnv->FindClass("java/lang/IllegalStateException");
    jniEnv->ThrowNew(illegalStateExceptionClass, message);
}

jobject createByteBuffer(JNIEnv *env, unsigned char *data, int size) {

    jbyteArray byteArray = env->NewByteArray(size);
    env->SetByteArrayRegion(byteArray, 0, size, (const jbyte *) data);
    jclass byteBufferClass = env->FindClass("java/nio/ByteBuffer");
    jmethodID wrapMethod = env->GetStaticMethodID(byteBufferClass, "wrap",
                                                  "([BII)Ljava/nio/ByteBuffer;");
    return env->CallStaticObjectMethod(byteBufferClass, wrapMethod, byteArray, 0, size);
}