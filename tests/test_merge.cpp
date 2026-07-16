#include "check.hpp"
#include "sealpack.hpp"

#include <cstdio>   // std::remove — portable unlink
#include <string>

using namespace sealpack;

// CWD-relative so it's portable to Windows (no /tmp there). Two different files,
// so opening both at once is fine on Windows (same-file double-open isn't).
static const char* kTgt = "sealpack_test_merge_target.spk";
static const char* kSrc = "sealpack_test_merge_source.spk";

TEST_MAIN("merge") {
    std::remove(kTgt);
    std::remove(kSrc);

    // Deployed pack.
    {
        auto t = Pack::create(kTgt, "pw");
        CHECK(t != nullptr);
        t->put("models/a.axmodel", std::string("A-v1"));
        t->put("models/b.axmodel", std::string("B-v1"));   // to be deleted by the patch
        t->put("cfg/keep.yaml",    std::string("keep"));   // untouched by the patch
        CHECK(t->commit());
    }
    // The "patch" is just a small pack — here under its OWN password (different
    // master key), which is fine: merge reads plaintext and re-encrypts under the
    // target's key. It updates a, adds c, and carries a `.spkdel` to remove b.
    {
        auto s = Pack::create(kSrc, "srcpw");
        CHECK(s != nullptr);
        s->put("models/a.axmodel", std::string("A-v2-updated"));   // overwrite
        s->put("models/c.axmodel", std::string("C-new"));          // add
        s->put(".spkdel", std::string("models/b.axmodel\n# a comment\n\n"));
        CHECK(s->commit());
    }

    // ---- merge the patch into the deployed pack ----
    {
        auto t = Pack::open(kTgt, "pw");
        auto s = Pack::open(kSrc, "srcpw");
        CHECK(t != nullptr);
        CHECK(s != nullptr);
        CHECK(t->merge(*s));       // buffered
        CHECK(t->commit());

        std::string x;
        CHECK(t->get("models/a.axmodel", &x)); CHECK(x == "A-v2-updated");  // overwritten
        CHECK(t->get("models/c.axmodel", &x)); CHECK(x == "C-new");         // added
        CHECK(t->get("cfg/keep.yaml",    &x)); CHECK(x == "keep");          // untouched
        CHECK(!t->has("models/b.axmodel"));    // deleted via .spkdel
        CHECK(!t->has(".spkdel"));             // control file consumed, not merged
        CHECK_EQ(t->list().size(), static_cast<size_t>(3));                 // a, c, keep
    }

    // ---- persisted, and re-merging is an idempotent no-op ----
    {
        auto t = Pack::open(kTgt, "pw");
        auto s = Pack::open(kSrc, "srcpw");
        CHECK(t != nullptr);
        CHECK(s != nullptr);
        CHECK(t->merge(*s));
        CHECK(t->commit());
        CHECK_EQ(t->list().size(), static_cast<size_t>(3));
        CHECK(!t->has("models/b.axmodel"));
        CHECK(!t->has(".spkdel"));
        std::string x;
        CHECK(t->get("models/a.axmodel", &x)); CHECK(x == "A-v2-updated");
    }

    std::remove(kTgt);
    std::remove(kSrc);
}
