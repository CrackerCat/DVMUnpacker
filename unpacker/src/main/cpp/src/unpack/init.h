//
// Created by 邓维佳 on 2018/3/14.
//

#ifndef XPOSEDDEMO_INIT_H
#define XPOSEDDEMO_INIT_H

#include <string>
#include<android/log.h>
#include "libdex/common.h"
//#define TAG "unshellnative" // 这个是自定义的LOG的标识
//#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__)
//#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__)
//#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__)
//#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__)
//#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

void initDvmFunctionTables();

void *findFunction(char const *functionName, void *libVMhandle);
int apiLevel();
void getProcessName(int pid, char *name, int len);

void toHex(char *destination, const char *source, int sourceLength);

jobject createArrayList(JNIEnv *jniEnv);

jboolean addToArrayList(JNIEnv *jniEnv, jobject arrayList, jobject element);

void threwIllegalStateException(JNIEnv *jniEnv, const char *message);

jobject createByteBuffer(JNIEnv *jniEnv,unsigned char * data,int size);

#ifdef __cplusplus
}
#endif


#endif //XPOSEDDEMO_INIT_H
