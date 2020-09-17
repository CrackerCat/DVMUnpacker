#ifndef RATEL2_ART_H
#define RATEL2_ART_H

#include <android/log.h>
#define GCRoot uint32_t

typedef size_t Size;

namespace art {
    namespace mirror {
        class Object {
        public:
        };


        class ArtMethod {

        public:
            uint32_t getAccessFlags();

            bool isAbstract();

            bool isNative();

            uint32_t getDexMethodIndex();

            uint32_t getDexCodeItemIndex();
        };
    }
}


#define TAG_UNPACK "unpack"

#define UNPACK_LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG_UNPACK ,__VA_ARGS__)
#define UNPACK_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG_UNPACK ,__VA_ARGS__)
#define UNPACK_LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG_UNPACK ,__VA_ARGS__)
#define UNPACK_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG_UNPACK ,__VA_ARGS__)


#define ANDROID_K 19
#define ANDROID_L 21
#define ANDROID_L2 22
#define ANDROID_M 23
#define ANDROID_N 24
#define ANDROID_N2 25
#define ANDROID_O 26
#define ANDROID_O2 27
#define ANDROID_P 28
//could not 29
#define ANDROID_Q 29
#define ANDROID_R 30


// paths

union JValue {
    uint8_t z;
    int8_t b;
    uint16_t c;
    int16_t s;
    int32_t i;
    int64_t j;
    float f;
    double d;
    art::mirror::Object *l;
};

#endif //RATEL2_ART_H
