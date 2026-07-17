cmake_minimum_required(VERSION 3.16)
project(sealpack LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 64-bit file offsets everywhere (harmless on 64-bit / MSVC): on 32-bit-off_t
# targets like the Android NDK, this is what lets a >2 GiB pack pread/pwrite and
# lseek without truncating the offset. Must be set before any system header, so
# push it onto every TU's command line.
add_compile_definitions(_FILE_OFFSET_BITS=64)

# ---- vendored monocypher (zero external deps) -------------------------------
add_library(monocypher STATIC third_party/monocypher/monocypher.c)
target_include_directories(monocypher PUBLIC third_party/monocypher)

# ---- vendored linenoise-ng (CLI line editing + tab completion, all 3 OSes) ---
# Also zero external deps; used only by the CLI shell, not the core library.
add_library(linenoise STATIC
    third_party/linenoise/linenoise.cpp
    third_party/linenoise/ConvertUTF.cpp
    third_party/linenoise/wcwidth.cpp)
target_include_directories(linenoise PUBLIC third_party/linenoise)

# ---- sealpack core library --------------------------------------------------
# The OS-specific file I/O + RNG live behind the os:: seam (src/os.hpp); pick the
# backend for this platform. Everything else in the core is portable C++17.
if(WIN32)
    set(SEALPACK_OS_BACKEND src/os_win32.cpp)
else()
    set(SEALPACK_OS_BACKEND src/os_posix.cpp)
endif()

add_library(sealpack STATIC
    src/crypto.cpp
    src/index.cpp
    src/store.cpp
    src/pack.cpp
    src/capi.cpp
    ${SEALPACK_OS_BACKEND}
)
target_include_directories(sealpack
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(sealpack PRIVATE monocypher)
if(WIN32)
    target_link_libraries(sealpack PRIVATE bcrypt)   # BCryptGenRandom (OS CSPRNG)
endif()
# MSVC lacks -Wall/-Wextra semantics; only pass them to GCC/Clang.
if(NOT MSVC)
    target_compile_options(sealpack PRIVATE -Wall -Wextra)
endif()

# ---- CLI (with the `web` file-manager UI) -----------------------------------
# Console/editor specifics sit behind the cli/platform.hpp shim (backends
# platform_posix.cpp / platform_win32.cpp), so the CLI builds on all three OSes.
# httplib is header-only and cross-platform (needs ws2_32 on Windows). The CLI
# reaches into src/ for sealpack::random_bytes (the web CSRF token).
if(WIN32)
    set(SEALPACK_CLI_PLATFORM cli/platform_win32.cpp)
else()
    set(SEALPACK_CLI_PLATFORM cli/platform_posix.cpp)
endif()

add_executable(sealpack-cli cli/main.cpp cli/web.cpp ${SEALPACK_CLI_PLATFORM})
target_link_libraries(sealpack-cli PRIVATE sealpack linenoise)
target_include_directories(sealpack-cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/httplib
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
find_package(Threads REQUIRED)
target_link_libraries(sealpack-cli PRIVATE Threads::Threads)
if(WIN32)
    target_link_libraries(sealpack-cli PRIVATE ws2_32)   # httplib sockets
endif()
set_target_properties(sealpack-cli PROPERTIES OUTPUT_NAME sealpack)

# ---- tests: one per module, each its own ctest ------------------------------
option(SEALPACK_BUILD_TESTS "Build unit tests" ON)
if(SEALPACK_BUILD_TESTS)
    enable_testing()
    # Add a module here as its test file lands. Each → its own test_<name> exe
    # + `ctest` entry, so failures point straight at the module.
    set(SEALPACK_TESTS
        crypto
        index
        store
        pack
        merge
        crash
    )
    foreach(t ${SEALPACK_TESTS})
        add_executable(test_${t} tests/test_${t}.cpp)
        target_link_libraries(test_${t} PRIVATE sealpack monocypher)
        target_include_directories(test_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()

    # C ABI smoke — pure C source, C++ linker (the lib is C++). Proves the C
    # header is valid C and the ABI links clean, like an FFI consumer would.
    add_executable(test_capi tests/test_capi.c)
    set_target_properties(test_capi PROPERTIES LINKER_LANGUAGE CXX)
    target_link_libraries(test_capi PRIVATE sealpack monocypher)
    add_test(NAME capi COMMAND test_capi)

    # End-to-end CLI smoke: drives the real `sealpack` binary (create/add/ls/cat/
    # get/merge + .spkdel) so CLI regressions get caught, not just the library.
    # Cross-platform via a CMake -P script (execute_process + `cmake -E env`).
    add_test(NAME cli COMMAND ${CMAKE_COMMAND}
        -DEXE=$<TARGET_FILE:sealpack-cli>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.cmake)
endif()
