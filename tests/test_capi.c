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

    // ---- merge: overlay a small "patch" pack (overwrite + add + .spkdel delete) ----
    const char* upath = "sealpack_test_capi_update.spk";
    remove(upath);
    sealpack_t* up = sealpack_create(upath, "hunter2");
    CHECK(up != NULL);
    CHECK(sealpack_put(up, "b/x.bin", "WORLD", 5) == SEALPACK_OK);        // overwrite
    CHECK(sealpack_put(up, "new.bin", "NEW", 3) == SEALPACK_OK);          // add
    CHECK(sealpack_put(up, ".spkdel", "a/y.bin\n", 8) == SEALPACK_OK);    // remove a/y.bin
    CHECK(sealpack_commit(up) == SEALPACK_OK);

    sp = sealpack_open(path, "hunter2");
    CHECK(sp != NULL);
    CHECK(sealpack_merge(sp, up) == SEALPACK_OK);   // buffered; commit persists it
    CHECK(sealpack_commit(sp) == SEALPACK_OK);
    sealpack_close(up);

    CHECK(sealpack_get(sp, "b/x.bin", &out, &n) == SEALPACK_OK);
    CHECK(n == 5 && memcmp(out, "WORLD", 5) == 0);  // overwritten by the patch
    sealpack_free(out);
    CHECK(sealpack_has(sp, "new.bin") == 1);        // added
    CHECK(sealpack_has(sp, "a/y.bin") == 0);        // deleted via .spkdel
    CHECK(sealpack_has(sp, ".spkdel") == 0);        // control file consumed, not merged
    CHECK(sealpack_has(sp, "a/z.bin") == 1);        // untouched
    sealpack_close(sp);
    remove(upath);

    remove(path);
    fprintf(stderr, "[capi] %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
