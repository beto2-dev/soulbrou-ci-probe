cmake_minimum_required(VERSION 3.22.1)
project("soulbrou")

# ------------------------------------------------------------------
# Soulbrou native components
#
# Two libraries are produced:
#   - soulbrou:          bundled with the Soulbrou application itself.
#   - soulbrou-runtime:  the runtime injected into protected APKs.
#
# Both share the same sources; the runtime library is the injectable
# artifact and must stay self contained (no dependency on the app).
# ------------------------------------------------------------------

set(SOULBROU_SOURCES
    runtime/runtime_core.cpp
    runtime/crypto.cpp
    runtime/platform.cpp
    runtime/zip_reader.cpp
    runtime/dalvik_interp.cpp
    protection/anti_analysis.cpp
    protection/anti_tampering.cpp
    protection/protection_chain.cpp
)

add_library(soulbrou SHARED
    ${SOULBROU_SOURCES}
    jni/soulbrou_jni.cpp
)

target_include_directories(soulbrou PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(soulbrou PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -ffp-contract=off
)

# Exported runtime symbols keep default visibility.
set_source_files_properties(
    jni/soulbrou_jni.cpp
    PROPERTIES
    COMPILE_OPTIONS "-fvisibility=default"
)

target_link_libraries(soulbrou
    android
    log
)

add_library(soulbrou-runtime SHARED
    ${SOULBROU_SOURCES}
    jni/soulbrou_jni.cpp
)

target_include_directories(soulbrou-runtime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(soulbrou-runtime PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -ffp-contract=off
)

set_source_files_properties(
    jni/soulbrou_jni.cpp
    PROPERTIES
    COMPILE_OPTIONS "-fvisibility=default"
)

target_link_libraries(soulbrou-runtime
    android
    log
)

# Strip unused sections on release builds.
set_target_properties(soulbrou PROPERTIES LINK_FLAGS "-Wl,--gc-sections")
set_target_properties(soulbrou-runtime PROPERTIES LINK_FLAGS "-Wl,--gc-sections")
