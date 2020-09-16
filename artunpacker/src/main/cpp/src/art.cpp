#include "cast.h"
#include "base.h"

using namespace art::mirror;
using namespace SandHook;

uint32_t ArtMethod::getAccessFlags() {
    return CastArtMethod::accessFlag->get(this);
}

uint32_t ArtMethod::getDexMethodIndex() {
    return CastArtMethod::dexMethodIndex->get(this);
}

uint32_t ArtMethod::getDexCodeItemIndex() {
    return CastArtMethod::dexCodeItemIndex->get(this);
}


bool ArtMethod::isAbstract() {
    uint32_t accessFlags = getAccessFlags();
    return ((accessFlags & 0x0400u) != 0);
}

bool ArtMethod::isNative() {
    uint32_t accessFlags = getAccessFlags();
    return ((accessFlags & 0x0100u) != 0);
}