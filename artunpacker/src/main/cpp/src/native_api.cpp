//
// Created by SwiftGan on 2019/4/12.
//

#include <syscall.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <jni.h>
#include <inlinehook_32/inlineHook.h>
#include "base.h"
#include "dlfcn_nougat.h"
#include "native_api.h"


extern int SDK_INT;

extern "C" {
int inline getArrayItemCount(char *const array[]) {
    int i;
    for (i = 0; array[i]; ++i);
    return i;
}

//for Android R
void *jniIdManager = nullptr;
ArtMethod *(*origin_DecodeArtMethodId)(void *thiz, jmethodID jmethodId) = nullptr;
ArtMethod *replace_DecodeArtMethodId(void *thiz, jmethodID jmethodId) {
    jniIdManager = thiz;
    return origin_DecodeArtMethodId(thiz, jmethodId);
}


// paths

const char *art_lib_path;


void initHideApi() {
#if defined(__aarch64__)

    if (SDK_INT >= ANDROID_Q) {
        art_lib_path = "/lib64/libart.so";
    } else {
        art_lib_path = "/system/lib64/libart.so";
    }

#elif defined(__arm__)
    if (SDK_INT >= ANDROID_Q) {
        art_lib_path = "/lib/libart.so";
    } else {
        art_lib_path = "/system/lib/libart.so";
    }
#endif

    if (SDK_INT >= ANDROID_R) {
        const char *symbol_decode_method = sizeof(void *) == 8
                                           ? "_ZN3art3jni12JniIdManager15DecodeGenericIdINS_9ArtMethodEEEPT_m"
                                           : "_ZN3art3jni12JniIdManager15DecodeGenericIdINS_9ArtMethodEEEPT_j";
        void *decodeArtMethod = getSymCompat(art_lib_path, symbol_decode_method);
        if (decodeArtMethod != nullptr) {


#if defined(__aarch64__)
            A64HookFunction(decodeArtMethod, (void *) replace_DecodeArtMethodId, (void **) &origin_DecodeArtMethodId)
#else
            if (registerInlineHook((uint32_t) decodeArtMethod, (uint32_t) replace_DecodeArtMethodId,
                                   (uint32_t **) &origin_DecodeArtMethodId) != ELE7EN_OK) {
                UNPACK_LOGE("register hook failed");
                return;
            }

            if (inlineHook((uint32_t) decodeArtMethod) != ELE7EN_OK) {
                UNPACK_LOGE("register hook failed");
                return;
            }
#endif // defined(__aarch64__)
        }
    }

}


static bool isIndexId(jmethodID mid) {
    return (reinterpret_cast<uintptr_t>(mid) % 2) != 0;
}

ArtMethod *getArtMethod(jmethodID jmethodId) {
    if (SDK_INT >= ANDROID_R && isIndexId(jmethodId)) {
        if (origin_DecodeArtMethodId == nullptr) {
            return reinterpret_cast<ArtMethod *>(jmethodId);
        }
        return origin_DecodeArtMethodId(jniIdManager, jmethodId);
    } else {
        return reinterpret_cast<ArtMethod *>(jmethodId);
    }
}


}
