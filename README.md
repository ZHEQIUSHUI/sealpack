# sealpack

A single-file, password-encrypted, content-addressed blob store with crash-safe
atomic commits. Think "an encrypted git packfile you can add/move/delete files
in" — one file on disk, many logical files inside, nothing readable without the
password.

**Zero external/system dependencies** — everything is vendored
([monocypher](https://monocypher.org) for crypto, cpp-httplib for the web UI,
linenoise-ng for the shell), so `git clone && cmake` just works, on device too.

> Maintaining sealpack? See [`docs/DESIGN.md`](docs/DESIGN.md) (architecture,
> on-disk format, invariants & gotchas) and [`docs/WORKLOG.md`](docs/WORKLOG.md)
> (what changed and why).

## Why

Shipping an encrypted bundle of models/files that gets updated over time.
LevelDB almost fits but sprays many small files and isn't encrypted. sealpack is
one file, encrypted, deduplicated, and safe across power loss.

## Properties

| | |
|---|---|
| **Single file** | header + append-only blobs + manifest + dual superblock |
| **Encrypted** | random master key + XChaCha20-Poly1305; the password wraps the master key via Argon2id. No password, no plaintext; no backdoor, no recovery key |
| **Change password** | `rekey` re-wraps the master key under a new password — one 88B slot rewritten, the data blobs never move, so it's instant on a multi-GB pack |
| **Deduplicated** | content-addressed (BLAKE2b): identical bytes stored once; `move`/`copy` are O(1) |
| **Crash-safe** | append-only + atomic double-superblock commit — a power loss leaves the old state or the new one, never half-written |
| **Incremental update** | `diff` builds a small `.spkpatch` of just the changed files; `patch` merges it into a deployed pack in place — ship a delta, not a multi-GB re-push. Encrypted under the pack's key and bound to its exact base version |
| **Two APIs** | C++ `Pack` class (core) + C ABI (`sealpack.h`) wrapper for FFI |
| **File-manager ready** | filesystem-style paths, `move`/`copy`/`list`(size+mtime)/`stat` — a UI splits paths on `/` into a folder tree |

## Use it

**C++**
```cpp
#include "sealpack.hpp"
auto pk = sealpack::Pack::create("models.sealpack", "hunter2");
pk->put("yolo/v2.axmodel", bytes);
pk->commit();                          // durable + atomic here

auto ro = sealpack::Pack::open("models.sealpack", "hunter2");  // null on bad pw
std::string data;
ro->get("yolo/v2.axmodel", &data);     // decrypts just this blob
```

**C**
```c
#include "sealpack.h"
sealpack_t* sp = sealpack_open("models.sealpack", "hunter2");
void* out; size_t n;
sealpack_get(sp, "yolo/v2.axmodel", &out, &n);
sealpack_free(out);
sealpack_close(sp);
```

**CLI** — an interactive shell: open once, type the password once, then run
commands against the still-open pack (one Argon2 unlock for the whole session).
Tab completes commands and in-pack paths (`cat yolo/`⇥); ↑/↓ recall history.
```bash
sealpack models.sealpack          # prompts for the password, then a mini shell:
  sealpack> ls
  sealpack> add cfg/x.json /tmp/x.json
  sealpack> cat yolo/<Tab>         # completes paths inside the pack
  sealpack> get yolo/v2.axmodel out.bin
  sealpack> rekey                 # change the password (asks the new one twice)
  sealpack> quit
```
One-shot subcommands remain for scripting — they prompt for the password on a
terminal, or read `$SEALPACK_PASSWORD` when there's no TTY (CI):
```bash
sealpack create models.sealpack                     # prompts for a new password twice
sealpack ls     models.sealpack
sealpack add    models.sealpack yolo/v2.axmodel model.bin
sealpack web    models.sealpack                     # browser file-manager (+ change-password panel)
```

## Incremental updates

Updated one model in a shipped pack? Send a patch, not the whole pack. `diff`
compares old→new and writes a `.spkpatch` with only the changed files; `patch`
merges it into the deployed pack in place.
```bash
sealpack diff  v1.sealpack v2.sealpack update.spkpatch   # producer: build the delta
sealpack patch deployed.sealpack update.spkpatch         # device: apply it (only the delta)
```
The patch is encrypted under the pack's own key (a patch for a different pack
won't decrypt) and refuses to apply unless the target is the exact base it was
built from — so you can't patch the wrong version. On device, the runtime calls
`sealpack_apply_patch()`. It's **file-level** (whole changed files): the payload
is binary models re-exported wholesale, so a byte-level diff would save nothing.

## On-disk format

```
0    Header       "SEALPACK" + version + Argon2 params (plaintext)
24   KeySlot[8]   88B: salt + AEAD-wrapped master key (slot 0 = the password; 1–7 reserved)
728  Superblock A ┐ 64B each, AEAD{seq, manifest_off, manifest_len} under the master key.
792  Superblock B ┘ active = larger seq with a valid MAC.
856  Data region  append-only: encrypted blobs + encrypted manifests (nonce|mac|cipher)
```

## Encryption — safe even with the source public

The data is encrypted under a **random master key**, never a password directly.
The password only *wraps* that master key into a key slot:
`password + salt → Argon2id → key-encryption key → wrap(master key)`. On disk
there's just the public salt, KDF parameters, ciphertext, and MACs — no secret
at rest. Security rests on the master key, not on hiding the algorithm
(Kerckhoffs's principle), so publishing this source changes nothing, and every
brute-force guess must pay a full Argon2id (memory-hard) run. A wrong password
unwraps to garbage → the AEAD MAC fails → open is refused.

**Changing the password is instant.** Because the master key is wrapped (not
derived), `rekey` just re-wraps it under the new password and rewrites one
88-byte slot — the data blobs are never re-encrypted, so it's instant even on a
multi-GB pack. An **empty password** (`""`) is accepted but wraps the key under a
public salt only, i.e. anyone can open it — use it solely for deliberately
unprotected/public packs.

(The header carries 8 key slots, so multi-password packs are possible at the
format level; the tooling deliberately exposes just one password — that's what
shipping model bundles needs.)

## Crash safety

Blobs are **append-only** (committed bytes are never overwritten). A commit:

1. `fsync` the appended blobs + manifest,
2. write the *inactive* superblock with `seq+1` pointing at the new manifest,
3. `fsync` it — this fsync is the single commit point.

Crash before step 3 finishes → the old superblock still wins (old state). A torn
superblock write → its MAC fails → the other slot is used. So open always sees a
fully-committed state; `tests/test_crash.cpp` corrupts superblocks and appends
junk tails to prove it.

## Build & test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # crypto / index / store / pack / patch / crash / capi
```

## Platforms

| | Core library (`Pack` + C ABI) | CLI + `web` UI |
|---|---|---|
| Linux / macOS | ✅ | ✅ |
| Windows | ✅ | ✅ |
| Android / cross | ✅ | — |

OS specifics sit behind two seams — `src/os.hpp` (core file I/O + RNG) and
`cli/platform.hpp` (console/editor) — each with a POSIX and a Win32 backend; the
rest is portable C++17. CI builds + tests on Linux, macOS, and Windows. See
[`docs/DESIGN.md`](docs/DESIGN.md) §14.

## License

The sealpack code is BSD-3-Clause. Vendored monocypher is CC0/BSD-2 (see
`third_party/monocypher`).
