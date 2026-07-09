#ifndef SEALPACK_TEST_CHECK_HPP
#define SEALPACK_TEST_CHECK_HPP

// Tiny zero-dependency test harness. Each test file:
//
//   #include "check.hpp"
//   TEST_MAIN("mymodule") {
//       CHECK(some_condition);
//       CHECK_EQ(a, b);
//   }
//
// Exits non-zero if any check failed (so ctest reports the failure).

#include <cstdio>

namespace sptest {
inline int& checks() { static int n = 0; return n; }
inline int& fails()  { static int n = 0; return n; }
}  // namespace sptest

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++sptest::checks();                                                    \
        if (!(cond)) {                                                         \
            ++sptest::fails();                                                 \
            std::fprintf(stderr, "  FAIL %s:%d  CHECK(%s)\n",                  \
                         __FILE__, __LINE__, #cond);                           \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                        \
    do {                                                                       \
        ++sptest::checks();                                                    \
        if (!((a) == (b))) {                                                   \
            ++sptest::fails();                                                 \
            std::fprintf(stderr, "  FAIL %s:%d  CHECK_EQ(%s, %s)\n",           \
                         __FILE__, __LINE__, #a, #b);                          \
        }                                                                      \
    } while (0)

#define TEST_MAIN(name)                                                       \
    static void sptest_body();                                                \
    int main() {                                                              \
        std::fprintf(stderr, "[%s]\n", name);                                 \
        sptest_body();                                                        \
        std::fprintf(stderr, "  %d checks, %d failed\n",                      \
                     sptest::checks(), sptest::fails());                      \
        return sptest::fails() ? 1 : 0;                                       \
    }                                                                         \
    static void sptest_body()

#endif  // SEALPACK_TEST_CHECK_HPP
