#include "check.hpp"
#include "sealpack.h"    // SEALPACK_ERR_* codes
#include "sealpack.hpp"

#include <cstdio>   // std::remove — portable unlink
#include <string>

using namespace sealpack;

// CWD-relative so it's portable to Windows (no /tmp there).
static const char* kOld = "sealpack_test_patch_old.spk";
static const char* kNew = "sealpack_test_patch_new.spk";

TEST_MAIN("patch") {
    std::remove(kOld);
    std::remove(kNew);

    // OLD state.
    {
        auto o = Pack::create(kOld, "pw");
        CHECK(o != nullptr);
        o->put("models/a.axmodel", std::string("A-v1"));
        o->put("models/b.axmodel", std::string("B-v1"));
        o->put("cfg/app.yaml",     std::string("cfg-v1"));
        o->put("stale.txt",        std::string("bye"));   // removed in NEW
        CHECK(o->commit());
    }
    // NEW state — deliberately under a DIFFERENT password, so it has a different
    // master key (proves the patch carries plaintext, not key-bound ciphertext).
    {
        auto n = Pack::create(kNew, "pw2");
        CHECK(n != nullptr);
        n->put("models/a.axmodel", std::string("A-v2-completely-different"));  // changed
        n->put("models/b.axmodel", std::string("B-v1"));                       // unchanged
        n->put("cfg/app.yaml",     std::string("cfg-v2"));                     // changed
        n->put("models/c.axmodel", std::string("C-new"));                      // added
        n->put("dup1.bin",         std::string("SAME"));   // two new paths, one blob:
        n->put("dup2.bin",         std::string("SAME"));   // the patch must dedup them
        CHECK(n->commit());
    }

    // ---- diff: build the patch old -> new ----
    std::string patch;
    {
        auto o = Pack::open(kOld, "pw");
        auto n = Pack::open(kNew, "pw2");
        CHECK(o != nullptr);
        CHECK(n != nullptr);
        CHECK(o->create_patch(*n, &patch));
        CHECK(!patch.empty());
    }

    // ---- apply to the base (kOld is exactly that base) → becomes new's content ----
    {
        auto dev = Pack::open(kOld, "pw");
        CHECK(dev != nullptr);
        CHECK(dev->apply_patch(patch));
        std::string s;
        CHECK(dev->get("models/a.axmodel", &s)); CHECK(s == "A-v2-completely-different");
        CHECK(dev->get("models/b.axmodel", &s)); CHECK(s == "B-v1");
        CHECK(dev->get("cfg/app.yaml",     &s)); CHECK(s == "cfg-v2");
        CHECK(dev->get("models/c.axmodel", &s)); CHECK(s == "C-new");
        CHECK(dev->get("dup1.bin",         &s)); CHECK(s == "SAME");
        CHECK(dev->get("dup2.bin",         &s)); CHECK(s == "SAME");
        CHECK(!dev->has("stale.txt"));                         // deletion propagated
        CHECK_EQ(dev->list().size(), static_cast<size_t>(6));
    }
    // persisted across reopen
    {
        auto dev = Pack::open(kOld, "pw");
        CHECK(dev != nullptr);
        std::string s;
        CHECK(dev->get("models/c.axmodel", &s));
        CHECK(s == "C-new");
    }

    // ---- double-apply is refused: kOld's state is now "new", the patch's base
    // is "old" → logical fingerprint mismatch (SEALPACK_ERR_PATCH) ----
    {
        auto dev = Pack::open(kOld, "pw");
        CHECK(dev != nullptr);
        CHECK(!dev->apply_patch(patch));
        CHECK_EQ(dev->last_error(), SEALPACK_ERR_PATCH);
    }

    // ---- wrong pack: kNew has a different master key → the patch (sealed under
    // old's master key) won't even decrypt (SEALPACK_ERR_AUTH) ----
    {
        auto n = Pack::open(kNew, "pw2");
        CHECK(n != nullptr);
        CHECK(!n->apply_patch(patch));
        CHECK_EQ(n->last_error(), SEALPACK_ERR_AUTH);
    }

    // ---- empty diff (logically identical packs) applies as a clean no-op ----
    // After the round-trip kOld holds exactly new's content, same as kNew, so the
    // delta between them is empty. Two handles to two *different* files: opening
    // the SAME file twice read-write is a sharing violation on Windows (and an
    // unsupported concurrent-writer scenario), so don't rely on POSIX letting it.
    {
        auto oldNow = Pack::open(kOld, "pw");    // now == new state
        auto n      = Pack::open(kNew, "pw2");
        CHECK(oldNow != nullptr);
        CHECK(n != nullptr);
        std::string p2;
        CHECK(oldNow->create_patch(*n, &p2));    // identical content → empty delta
        CHECK(oldNow->apply_patch(p2));          // no-op, base matches
        CHECK_EQ(oldNow->list().size(), static_cast<size_t>(6));
    }

    std::remove(kOld);
    std::remove(kNew);
}
