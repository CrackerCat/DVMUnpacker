//
// Created by 邓维佳 on 2020/8/28.
// 脱壳机，
//

#ifndef RATEL2_UNPACKER_H
#define RATEL2_UNPACKER_H

#include <android/log.h>
#include <map>
#include <string>

#include "base.h"



class DexFileHolder {
private:
    std::map<uint32_t, bool> dumped_method;
    std::string dumpWorkDir;

public:
    std::string method_dump_dirs;

    DexFileHolder(std::string dumpWorkDir);

    void dumpMethod(art::mirror::ArtMethod *artMethod);

    bool valid() {
        return size_ > 32;
    }

    const uint8_t *begin_ = nullptr;
    size_t size_ = 0;


};

class Unpacker {

public:


    void setOpenFlag(bool open_status) {
        this->open = open_status;
    }

    void init(std::string dump_work_dir);

    std::string prettyMethod(art::mirror::ArtMethod *artMethod) {
        return prettyMethod_handler(artMethod, true);
    }


    void handleMethodDump(art::mirror::ArtMethod *artMethod);

private:
    bool open = false;

    std::map<void *, DexFileHolder *> dex_file_holder_map;

    std::string dumpWorkDir;

    std::string
    (*prettyMethod_handler)(art::mirror::ArtMethod *artMethod, bool with_signature) = nullptr;

    void *(*getObsoleteDexCache_handle)(art::mirror::ArtMethod *artMethod) = nullptr;

    void *(*getDexFile_handle)(art::mirror::ArtMethod *artMethod) = nullptr;

    DexFileHolder *get_or_create_dex_image(void *dex_file_handle);

    void dumpRawDex(DexFileHolder *dexFileHolder);


    void *getDexFile(art::mirror::ArtMethod *pMethod);
};

extern Unpacker UnpackerInstance;

#endif //RATEL2_UNPACKER_H