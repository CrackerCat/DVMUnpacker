//
// Created by 邓维佳 on 2018/3/13.
//

#include "oo/Object.h"
#include <malloc.h>
#include <string>
#include "DvmFunctionTable.h"
#include "init.h"

extern "C"
JNIEXPORT jobject JNICALL
Java_com_virjar_dvmunpacker_unpacker_unpack_Dumper_originDex(JNIEnv *env, jclass type,
                                                             jclass loader) {
    // check init
    if (dvmFunctionTables.dvmDecodeIndirectRef == nullptr) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        jclass newExcCls = env->FindClass("java/lang/IllegalStateException");
        env->ThrowNew(newExcCls, "函数表初始化失败,当前脱壳只支持在dalvik下，请确认您的手机环境不是art模式");
        return nullptr;
    }
    auto *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            loader);
    DvmDex *dvm_dex = clazz->pDvmDex;
    return env->NewDirectByteBuffer(dvm_dex->memMap.addr, dvm_dex->memMap.length);
}


uint8_t *codeitem_end(const u1 **pData) {
    uint32_t num_of_list = readUnsignedLeb128(pData);
    for (; num_of_list > 0; num_of_list--) {
        int32_t num_of_handlers = readSignedLeb128(pData);
        int num = num_of_handlers;
        if (num_of_handlers <= 0) {
            num = -num_of_handlers;
        }
        for (; num > 0; num--) {
            readUnsignedLeb128(pData);
            readUnsignedLeb128(pData);
        }
        if (num_of_handlers <= 0) {
            readUnsignedLeb128(pData);
        }
    }
    return (uint8_t *) (*pData);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_virjar_dvmunpacker_unpacker_unpack_Dumper_getMethodAccessFlagsWithDescriptor(JNIEnv *env,
                                                                                      jclass type,
                                                                                      jstring methodDescriptor_,
                                                                                      jstring methodName_,
                                                                                      jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);

    auto *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == nullptr) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }

    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    if (method == nullptr) {
        return -1;
    }
    return method->accessFlags;
}


uint32_t accessFlagsMask = 0x3ffff;

extern "C"
JNIEXPORT jobject JNICALL
Java_com_virjar_dvmunpacker_unpacker_unpack_Dumper_methodDataWithDescriptor(JNIEnv *env,
                                                                            jclass type,
                                                                            jstring methodDescriptor_,
                                                                            jstring methodName_,
                                                                            jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    auto *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = nullptr;
    DexCode *code = nullptr;
    uint8_t *item = nullptr;
    uint32_t ac = 0;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == nullptr) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == nullptr) {
        goto end;
    }

    //check for native
    ac = (method->accessFlags) & accessFlagsMask;
    if (method->insns == nullptr || ac & ACC_NATIVE) {
        goto end;
    }

    //why 16
    // 2 byte for registersSize
    // 2 byte for insSize
    // 2 byte for outsSize
    // 2 byte for triesSize
    // 4 byte for debugInfoOff
    // 4 byte for insnsSize
    // and then ,the insns address
    code = (DexCode *) ((const u1 *) method->insns - 16);
    item = (uint8_t *) code;
    int code_item_len;
    if (code->triesSize) {
        const u1 *handler_data = dexGetCatchHandlerData(code);
        const u1 **phandler = &handler_data;
        uint8_t *tail = codeitem_end(phandler);
        code_item_len = (int) (tail - item);
    } else {
        //正确的DexCode的大小
        code_item_len = 16 + code->insnsSize * 2;
    }

    ret = env->NewDirectByteBuffer(item, code_item_len);

    end:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return ret;
}






extern "C"
JNIEXPORT jboolean JNICALL
Java_com_virjar_dvmunpacker_unpacker_unpack_Dumper_isClassDefined(JNIEnv *env, jclass type,
                                                                  jstring descriptor_,
                                                                  jobject classLoader_) {
    const char *descriptor = env->GetStringUTFChars(descriptor_, JNI_FALSE);
    Object *classLoader = dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(), classLoader_);
    ClassObject *theClass = dvmFunctionTables.dvmLookupClass(descriptor, classLoader, JNI_FALSE);
    env->ReleaseStringUTFChars(descriptor_, descriptor);
    return static_cast<jboolean>(theClass != nullptr ? JNI_TRUE : JNI_FALSE);
}

