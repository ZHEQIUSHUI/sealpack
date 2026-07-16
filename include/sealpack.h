#ifndef SEALPACK_H
#define SEALPACK_H

// sealpack — a single-file, password-encrypted, content-addressed blob store.
//
// One file on disk holds many logical files ("yolo/v2.axmodel", ...). Storage
// is content-addressed: identical bytes are stored once (dedup). Everything is
// encrypted with a key derived from a password (Argon2id) — nothing but the
// password can decrypt it, and there is no backdoor or recovery key. Writes are
// crash/power-fail safe: a commit is atomic (double-superblock swap), so a
// power loss leaves either the old committed state or the new one, never a
// half-written file.
//
// Pure C ABI so it drops into C / C++ / FFI with no C++ runtime coupling.
//
//   sealpack_t* sp = sealpack_create("models.sealpack", "hunter2");
//   sealpack_put(sp, "yolo/v2.axmodel", buf, n);
//   sealpack_commit(sp);                 // <- durable + atomic here
//   sealpack_close(sp);
//
//   sp = sealpack_open("models.sealpack", "hunter2");   // NULL on wrong pw
//   void* out; size_t n;
//   sealpack_get(sp, "yolo/v2.axmodel", &out, &n);      // decrypts just this
//   sealpack_free(out);
//   sealpack_close(sp);

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle. The tag is sealpack_handle (not "sealpack") so this stays
// usable alongside the C++ `namespace sealpack` when both headers are included.
typedef struct sealpack_handle sealpack_t;

typedef enum {
    SEALPACK_OK        =  0,
    SEALPACK_ERR_IO    = -1,  // file read/write failed
    SEALPACK_ERR_AUTH  = -2,  // wrong password or tampered data (MAC failed)
    SEALPACK_ERR_CORRUPT = -3,  // bad magic / version / structural integrity
    SEALPACK_ERR_NOTFOUND = -4,  // logical path not present
    SEALPACK_ERR_NOMEM = -5,
    SEALPACK_ERR_ARG   = -6,  // NULL / bad argument
    SEALPACK_ERR_EXISTS = -7,  // create() on an existing file
    SEALPACK_ERR_PATCH = -8,  // patch does not apply to this pack (wrong base)
} sealpack_status;

// ---- open / create / close --------------------------------------------------

// Create a fresh empty pack at `path`, encrypted under `password`.
// Returns NULL if the file already exists or on I/O error.
sealpack_t* sealpack_create(const char* path, const char* password);

// Open an existing pack. Returns NULL on wrong password, corruption, or I/O
// error — call sealpack_open_error() right after for the specific reason.
sealpack_t* sealpack_open(const char* path, const char* password);

// Reason for the most recent sealpack_open/create returning NULL (thread-local).
int sealpack_open_error(void);

// Close and free. Does NOT auto-commit — uncommitted put/del are dropped.
void sealpack_close(sealpack_t* sp);

// ---- CRUD (logical path -> bytes) -------------------------------------------

// Store `data` (size bytes) under logical `path`, e.g. "yolo/v2.axmodel".
// Deduped by content: identical bytes reuse one blob. Overwrites an existing
// path. Buffered in memory — becomes durable only at sealpack_commit.
int sealpack_put(sealpack_t* sp, const char* path, const void* data, size_t size);

// Read `path` into a newly malloc'd buffer (*out, *size); free with
// sealpack_free. Decrypts only that one blob (random access, no full unpack).
int sealpack_get(sealpack_t* sp, const char* path, void** out, size_t* size);

// Remove a logical path. The underlying blob's space is reclaimed at compact()
// once nothing else references it.
int sealpack_del(sealpack_t* sp, const char* path);

// 1 if `path` exists (committed or buffered), 0 if not.
int sealpack_has(sealpack_t* sp, const char* path);

// ---- file-manager ops (path layer — the blob never moves) -------------------

// Rename/move `from` -> `to`. O(1): only the path->blob mapping changes, so
// moving a huge model across "folders" copies nothing. Fails if `from` is
// absent or `to` already exists. Buffered until commit.
int sealpack_move(sealpack_t* sp, const char* from, const char* to);

// Copy `from` -> `to`: `to` points at the same blob (dedup — zero extra bytes).
// This is how one model lives under several names. Buffered until commit.
int sealpack_copy(sealpack_t* sp, const char* from, const char* to);

// ---- commit: the crash-safe atomic point ------------------------------------

// Flush all buffered put/del to disk atomically: append new blobs + manifest,
// then swap the active superblock (fsync-ordered). A power loss before this
// call returns completes leaves the previously committed state fully intact.
int sealpack_commit(sealpack_t* sp);

// ---- listing / maintenance --------------------------------------------------

typedef struct {
    const char* path;   // owned by sp — valid until close/next mutation
    size_t      size;   // plaintext size
    uint64_t    mtime;  // last-written unix seconds (UI "modified" column)
} sealpack_entry;

// Malloc a sorted array of every logical path (*entries, *count); free the
// array with sealpack_free (the path strings belong to sp, don't free them).
// The UI splits each path on '/' to render a folder tree.
int sealpack_list(sealpack_t* sp, sealpack_entry** entries, size_t* count);

// Metadata for one path. Returns SEALPACK_ERR_NOTFOUND if absent.
int sealpack_stat(sealpack_t* sp, const char* path, sealpack_entry* out);

// Rewrite the file dropping blobs no live path references (space reclaim).
// Atomic: writes a new file and swaps it in, so a crash keeps the old one.
int sealpack_compact(sealpack_t* sp);

// ---- incremental update (ship a delta, not the whole pack) ------------------

// Apply a `.spkpatch` (produced by `sealpack diff` / sealpack_create_patch) to
// this pack in place: only the changed files are added, removed ones deleted,
// then committed atomically. The patch is encrypted under this pack's master key
// — a patch for a different pack returns SEALPACK_ERR_AUTH — and it refuses with
// SEALPACK_ERR_PATCH unless this pack matches the base the patch was built from.
// This is the on-device path: download a small patch, apply it, no full re-push.
int sealpack_apply_patch(sealpack_t* sp, const void* patch, size_t size);

// Producer side: write a patch that turns `base` into `newer` into a freshly
// malloc'd buffer (*out, *size); free with sealpack_free. Carries only the files
// that differ, encrypted under `base`'s master key.
int sealpack_create_patch(sealpack_t* base, sealpack_t* newer, void** out, size_t* size);

// ---- password ---------------------------------------------------------------
// Data is under a random master key; the password only wraps it into an 88-byte
// slot, so changing it rewrites that slot alone — the data blobs never move, so
// it's instant even on a multi-GB pack. Empty password ("") is allowed but gives
// no protection (public salt → anyone opens it).

// Change the password. The old password stops working.
int sealpack_rekey(sealpack_t* sp, const char* new_password);

// ---- misc -------------------------------------------------------------------

void sealpack_free(void* p);
const char* sealpack_strerror(int status);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SEALPACK_H
