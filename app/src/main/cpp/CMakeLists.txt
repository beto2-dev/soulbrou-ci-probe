cmake_minimum_required(VERSION 3.22.1)
project("soulbrou")

add_library(soulbrou SHARED
    jni/soulbrou_jni.cpp
)

target_link_libraries(soulbrou
    android
    log
)

add_library(soulbrou-runtime SHARED
    jni/soulbrou_jni.cpp
)

target_link_libraries(soulbrou-runtime
    android
    log
)
