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

# ---- vendored monocypher (zero external deps) -------------------------------
add_library(monocypher STATIC third_party/monocypher/monocypher.c)
target_include_directories(monocypher PUBLIC third_party/monocypher)

# ---- sealpack core library --------------------------------------------------
add_library(sealpack STATIC
    src/crypto.cpp
    src/index.cpp
    src/store.cpp
    src/pack.cpp
    src/capi.cpp
)
target_include_directories(sealpack
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(sealpack PRIVATE monocypher)
target_compile_options(sealpack PRIVATE -Wall -Wextra)

# ---- CLI (with the `web` file-manager UI) -----------------------------------
add_executable(sealpack-cli cli/main.cpp cli/web.cpp)
target_link_libraries(sealpack-cli PRIVATE sealpack)
target_include_directories(sealpack-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/httplib)
find_package(Threads REQUIRED)
target_link_libraries(sealpack-cli PRIVATE Threads::Threads)
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
endif()
