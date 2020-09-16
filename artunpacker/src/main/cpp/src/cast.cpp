//
// Created by swift on 2019/2/3.
//


#include "cast.h"
#include "base.h"
#include <atomic>
#include "native_api.h"
#include <cstdio>

extern int SDK_INT;

jint getIntFromJava(JNIEnv *env, const char *className, const char *fieldName) {
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        printf("find class error !");
        return 0;
    }
    jfieldID id = env->GetStaticFieldID(clazz, fieldName, "I");
    if (id == nullptr) {
        printf("find field error !");
        return 0;
    }
    return env->GetStaticIntField(clazz, id);
}

namespace SandHook {

    class CastAccessFlag : public IMember<art::mirror::ArtMethod, uint32_t> {
    protected:
        Size calOffset(JNIEnv *jniEnv, art::mirror::ArtMethod *p) override {
            uint32_t accessFlag = getIntFromJava(jniEnv, "com/virjar/artunpacker/ArtUnPacker",
                                                 "testAccessFlag");
            if (accessFlag == 0) {
                accessFlag = 524313;
                //kAccPublicApi
                if (SDK_INT >= ANDROID_Q) {
                    accessFlag |= 0x10000000;
                }
            }
            int offset = findOffset(p, getParentSize(), 2, accessFlag);
            if (offset < 0) {
                if (SDK_INT >= ANDROID_N) {
                    return 4;
                } else if (SDK_INT == ANDROID_L2) {
                    return 20;
                } else if (SDK_INT == ANDROID_L) {
                    return 56;
                } else {
                    return getParentSize() + 1;
                }
            } else {
                return static_cast<size_t>(offset);
            }
        }
    };


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

    class CastDexCodeItemIndex : public IMember<art::mirror::ArtMethod, uint32_t> {
    protected:
        Size calOffset(JNIEnv *jniEnv, art::mirror::ArtMethod *p) override {
            if (SDK_INT >= ANDROID_P) {
                return CastArtMethod::accessFlag->getOffset()
                       + CastArtMethod::accessFlag->size();
            }
            return CastArtMethod::dexMethodIndex->getOffset()
                   - CastArtMethod::dexMethodIndex->size();
        }
    };


    void CastArtMethod::init(JNIEnv *env) {
        //init ArtMethodSize
        jclass sizeTestClass = env->FindClass("com/virjar/artunpacker/ArtMethodSizeTest");
        jmethodID artMethod1 = env->GetStaticMethodID(sizeTestClass, "method1", "()V");
        jmethodID artMethod2 = env->GetStaticMethodID(sizeTestClass, "method2", "()V");

        env->CallStaticVoidMethod(sizeTestClass, reinterpret_cast<jmethodID>(artMethod1));

        std::atomic_thread_fence(std::memory_order_acquire);

        art::mirror::ArtMethod *m1 = getArtMethod(artMethod1);
        art::mirror::ArtMethod *m2 = getArtMethod(artMethod2);

        size = m2 - m1;

        //init Members

        accessFlag = new CastAccessFlag();
        accessFlag->init(env, m1, size);

        dexMethodIndex = new CastDexMethodIndex();
        dexMethodIndex->init(env, m1, size);

        dexCodeItemIndex = new CastDexCodeItemIndex();
        dexCodeItemIndex->init(env, m1, size);


    }


    Size CastArtMethod::size = 0;

    IMember<art::mirror::ArtMethod, uint32_t> *CastArtMethod::dexMethodIndex = nullptr;
    IMember<art::mirror::ArtMethod, uint32_t> *CastArtMethod::accessFlag = nullptr;
    IMember<art::mirror::ArtMethod, uint32_t> *CastArtMethod::dexCodeItemIndex = nullptr;
}