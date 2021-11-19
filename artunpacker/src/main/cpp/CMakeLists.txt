cmake_minimum_required(VERSION 3.4.1)
message("Building ucrackNative for Android(${CMAKE_SYSTEM_PROCESSOR})...")

set(UCRACK_SOURCE
        src/Unpacker.cpp
        src/dlfcn_nougat.cpp
        src/elf_image.cpp
        src/process_map.cpp
        src/cast.cpp
        src/art.cpp
        src/native_api.cpp
        src/inlinehook_64/And64InlineHook.cpp
        src/inlinehook_32/inlineHook.cpp
        src/inlinehook_32/relocate.cpp
        )

set(LIBRARY_NAME "artunpacker")

include_directories(src)
include_directories(src/inlinehook_32)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -funwind-tables -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -funwind-tables -g")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")

add_library(${LIBRARY_NAME} SHARED ${UCRACK_SOURCE})


target_link_libraries(${LIBRARY_NAME} log)
