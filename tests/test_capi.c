// Pure-C smoke test of the C ABI (proves capi.h is valid C and links clean).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sealpack.h"

static int checks = 0, fails = 0;
#define CHECK(c)                                                              \
    do {                                                                       \
        ++checks;                                                              \
        if (!(c)) { ++fails; fprintf(stderr, "  FAIL %d: %s\n", __LINE__, #c); }\
    } while (0)

int main(void) {
    const char* path = "sealpack_test_capi.spk";
    remove(path);

    sealpack_t* sp = sealpack_create(path, "hunter2");
    CHECK(sp != NULL);
    CHECK(sealpack_put(sp, "a/x.bin", "HELLO", 5) == SEALPACK_OK);
    CHECK(sealpack_put(sp, "a/y.bin", "HELLO", 5) == SEALPACK_OK);  // dedup
    CHECK(sealpack_commit(sp) == SEALPACK_OK);
    CHECK(sealpack_has(sp, "a/x.bin") == 1);
    CHECK(sealpack_has(sp, "nope") == 0);

    void* out = NULL;
    size_t n = 0;
    CHECK(sealpack_get(sp, "a/x.bin", &out, &n) == SEALPACK_OK);
    CHECK(n == 5 && memcmp(out, "HELLO", 5) == 0);
    sealpack_free(out);

    // file-manager ops
    CHECK(sealpack_move(sp, "a/x.bin", "b/x.bin") == SEALPACK_OK);
    CHECK(sealpack_has(sp, "a/x.bin") == 0);
    CHECK(sealpack_has(sp, "b/x.bin") == 1);
    CHECK(sealpack_copy(sp, "a/y.bin", "a/z.bin") == SEALPACK_OK);
    CHECK(sealpack_commit(sp) == SEALPACK_OK);  // persist move/copy before reopen

    sealpack_entry* ents = NULL;
    size_t cnt = 0;
    CHECK(sealpack_list(sp, &ents, &cnt) == SEALPACK_OK);
    CHECK(cnt == 3);  // a/y.bin, a/z.bin, b/x.bin
    sealpack_free(ents);

    sealpack_entry st;
    CHECK(sealpack_stat(sp, "b/x.bin", &st) == SEALPACK_OK);
    CHECK(st.size == 5);
    sealpack_close(sp);

    // wrong password rejected; correct one round-trips
    CHECK(sealpack_open(path, "wrong") == NULL);
    sp = sealpack_open(path, "hunter2");
    CHECK(sp != NULL);
    CHECK(sealpack_get(sp, "b/x.bin", &out, &n) == SEALPACK_OK);
    CHECK(n == 5 && memcmp(out, "HELLO", 5) == 0);
    sealpack_free(out);
    sealpack_close(sp);

    remove(path);
    fprintf(stderr, "[capi] %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
