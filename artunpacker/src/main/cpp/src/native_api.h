//
// Created by SwiftGan on 2019/4/12.
//

#ifndef SANDHOOK_NATIVE_HOOK_H
#define SANDHOOK_NATIVE_HOOK_H


#if defined(__aarch64__)
# define __get_tls() ({ void** __val; __asm__("mrs %0, tpidr_el0" : "=r"(__val)); __val; })
#elif defined(__arm__)
# define __get_tls() ({ void** __val; __asm__("mrc p15, 0, %0, c13, c0, 3" : "=r"(__val)); __val; })
#endif

#define TLS_SLOT_ART_THREAD 7

using namespace art::mirror;

extern "C" {

void initHideApi();
ArtMethod *getArtMethod(jmethodID jmethodId);
//extern std::mutex jitMutex;
}

#endif //SANDHOOK_NATIVE_HOOK_H
