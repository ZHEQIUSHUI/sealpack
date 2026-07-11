# sealpack — design & maintenance notes

Audience: whoever maintains sealpack (not end users — for usage see `README.md`).
This is the "how it's built and why, and what will bite you" reference.

---

## 1. What it is / goals

A single-file, encrypted, content-addressed blob store. Think "an encrypted git
packfile you can `add`/`get`/`rm`/`mv`/`cp` files into", used to ship a set of
model files (and now also small config/text files) as **one password-protected
`.spk`**.

Design goals, in priority order:

1. **Confidential at rest** — no password, no plaintext. The source being public
   must not weaken it (Kerckhoffs).
2. **Crash-safe** — a power loss mid-write leaves either the old state or the new
   state, never a half-written pack.
3. **Cheap password change** — re-keying a multi-GB pack must be instant.
4. **Zero-dependency, portable** — vendored crypto, builds on Linux/macOS and
   cross-compiles for Android/AX with no system libs.
5. **Embeddable** — a clean C++ core + stable C ABI so a runtime can open a pack
   and load blobs straight from memory (no plaintext on disk).

Non-goals: concurrent multi-writer access, network serving (the `web` UI is a
localhost convenience, not a server), per-file passwords.

---

## 2. Module map

Layered, each with its own `ctest` target (CMake registers them via `foreach`):

```
crypto   monocypher wrapper: derive_key (Argon2id), AEAD (XChaCha20-Poly1305),
         BLAKE2b-256 content hash, OS RNG. No hand-rolled crypto — ever.
index    in-memory manifest: blobs[] (hash→offset/len) + paths[] (path→hash,
         +mtime). serialize/parse. normalize_path() rejects `..` escapes.
store    on-disk file layout + I/O: header, key slots, double superblock,
         append-only data region, atomic commit (durable_sync).
pack     the Pack class — ties crypto+index+store together. CRUD, move/copy
         (O(1), CAS), compact, rekey, verify_password. This is the core API.
capi     extern "C" wrapper over Pack (opaque handle) for non-C++ hosts.
```

CLI/UI sits on top (in `cli/`, only linked into the `sealpack` executable — the
core library never touches HTTP or a terminal):

```
cli/main.cpp     arg parsing, interactive shell, one-shot commands, password I/O
cli/web.cpp      `sealpack web` — localhost file-manager UI + REST API
cli/preview.hpp  shared text-vs-binary sniffing + MIME guess (cat + web preview)
```

Public headers: `include/sealpack.hpp` (C++ `Pack`) and `include/sealpack.h`
(C ABI). Nothing in `src/` is a public header.

---

## 3. On-disk format (v2)

Fixed-offset front matter, then an append-only data region. Authoritative
constants live in `src/store.cpp` (`kHeaderSize` … `kDataStart`).

```
off   size            what
0     24              Header:  "SEALPACK" magic(8) + version u32(=2) + Argon2 params(3×u32)
24    88 × 8 = 704    KeySlot[8]: each = salt(16) + AEAD-wrapped master key(72)
728   64              Superblock A ┐ AEAD{seq u64, root_off u64, root_len u64}
792   64              Superblock B ┘ under the MASTER key (nonce24+mac16+cipher24)
856   …               Data region: append-only encrypted blobs + manifests
```

- **Master key** is a random 32 bytes, generated at `create`. It — not the
  password — encrypts the superblocks and every data blob.
- Each **KeySlot** holds `AEAD_wrap(master_key)` under a KEK =
  `Argon2id(password, slot.salt)`. Opening tries each non-empty slot until one
  unwraps. (The 8-slot array is a LUKS-style holdover from a multi-password
  phase — see WORKLOG. Today only **slot 0** is used, but the on-disk shape kept
  the array so the format didn't churn.)
- **root_off/root_len** in the active superblock point at the current serialized
  manifest (index) in the data region.

Wrapped-key size = `kNonceBytes(24) + kMacBytes(16) + kKeyBytes(32) = 72`.
Slot size = `kSaltBytes(16) + 72 = 88`.

### v1 → v2 is NOT compatible

v1 derived the data key directly from the password (no master key, no slots).
v2 (`kVersion = 2`) inserted the 704-byte slot array, so **every offset moved**
(superblocks 40/104 → 728/792, data 168 → 856). There is no in-place upgrade;
v1 packs must be re-created. Any test or tool that hardcodes offsets must use the
v2 numbers (this bit `test_crash` once — it had 40/104 baked in).

---

## 4. Key-wrapping & rekey

Why: re-deriving and re-encrypting a multi-GB pack on every password change is
unacceptable. With key-wrapping the data is encrypted under the master key, which
never changes; the password only protects the *wrapped copy* of it.

`rekey(new_password)`:
1. Unwrap the master key from an existing slot (proves the caller's authority —
   in practice the pack is already open, so opening *was* the proof).
2. Fresh random salt → `Argon2id(new_password, salt)` → KEK.
3. `AEAD_wrap(master_key)` under the new KEK → write the single 88-byte slot 0
   (one `pwrite` + `fsync`). **The data region is never touched** → instant.

`verify_password` just attempts an unwrap. Empty password is allowed (wraps under
a KEK derived from ""), which means *no protection* — the CLI/web warn about it.

---

## 5. Crash safety

Invariant: **either the old committed state or the new one, never a mix.**

- **Data blobs are append-only.** A new blob is written past the end; nothing
  in-place is ever overwritten. A crash mid-append just leaves junk past the last
  committed superblock, which is ignored on next open (the manifest doesn't
  reference it).
- **Double superblock, alternating.** Commit writes the *inactive* superblock
  (A/B) with `seq = active.seq + 1`, then fsyncs. Open picks the superblock with
  the **larger seq and a valid MAC**. The superblock fsync is the single atomic
  commit point: before it, the old superblock is still active; after it, the new
  one is. A torn superblock write fails its MAC → the other (older) one wins.
- **`durable_sync` is platform-split** (`src/store.cpp`):
  - Linux: `fdatasync` (data-only, faster).
  - macOS: **`fcntl(F_FULLFSYNC)`** — plain `fsync` on macOS only pushes to the
    drive cache, not the platter; `fdatasync` doesn't exist. `F_FULLFSYNC` is the
    real barrier. (Fixed in `e2e2792` after macOS CI surfaced it.)

`test_crash` exercises this: truncated/corrupt superblocks, junk tails → verifies
the pack still opens to the last good state.

---

## 6. Content addressing / dedup

Blobs are keyed by **BLAKE2b-256(content)**. Identical content is stored once.
`move`/`copy` are O(1): they only edit the path→hash map, never the blob. This is
the CAS sweet spot and why `cp` of a 400 MB model is free. `compact` walks live
hashes and rewrites the data region without the garbage (the only O(n) op).

---

## 7. CLI surface

`cli/main.cpp`. Two entry modes share one `do_command(Pack*, args)`:

- **Interactive shell** — `sealpack <pack>`: prompt for the password once
  (termios echo off, never in argv/history), open, drop into a mini shell that
  reuses the open pack (one Argon2 for the whole session).
- **One-shot** — `sealpack <cmd> <pack> [args]`: on a TTY prompts for the
  password; non-TTY reads `$SEALPACK_PASSWORD` (for scripts/CI).

Commands: `create add get cat edit ls rm mv cp stat compact rekey web`.
`ls`/`stat` print human-readable sizes (`human_size`). `is_command()` and both
help texts (`shell_help`, `usage`) must be kept in sync when adding a command.

- **`cat <path>`** — decrypt + print, but only if `looks_text` (§9); binary is
  refused with a pointer to `get`.
- **`edit <path>`** — decrypt to a 0600 temp file (kept with the original
  extension so the editor gets syntax mode), launch `$VISUAL`/`$EDITOR`
  (default `vi`), read back, and if changed `put`+`commit`. No change → no
  rewrite. Binary or non-TTY is refused. `edit_in_editor()` uses `mkstemps` for
  the suffix.

---

## 8. Web UI

`sealpack web <pack> [port]` → localhost file manager. The C++ side holds the
open pack + master key; the browser only draws UI and calls a REST API.

- **Bound to 127.0.0.1 only.** Every `/api/*` call must carry a per-start session
  **token** (header `X-Sealpack-Token` or `?t=`), so another site (CSRF) or a
  stray same-host process can't drive it.
- REST: `GET /api/list`, `GET /api/get` (download, attachment),
  `GET /api/view` (inline preview, §9), `POST /api/put|del|move|copy|rekey`.
  Every mutating call auto-commits.
- Front-end is one embedded HTML/JS string (`kIndexHtml`), vanilla, no build
  step. `%%TOKEN%%` is replaced per server start. Folder-tree navigation +
  breadcrumb over the flat path list; a **right-docked preview/edit panel**.

The core library never links httplib — it's `cli/`-only. httplib is vendored in
`third_party/httplib`.

---

## 9. Human-readable preview & edit

Shared logic in `cli/preview.hpp` (used by both `cat` and the web `/api/view`)
so terminal and browser agree on what's safe to render.

- **`looks_text(bytes)`** — scans the head (≤8 KiB): a NUL byte → binary;
  >5% C0 control chars (excluding tab/newline/CR) → binary; bytes ≥ 0x80 are
  **not** counted, so UTF-8 stays text.
- **`mime_by_ext(path)`** — for inline rendering. Only image types are meant to
  be *rendered*; `html/svg/js/css` deliberately map to `text/plain` so the
  browser shows their **source** rather than executing them (the pack could hold
  a hostile `.svg`/`.html`, and the web UI is same-origin with the token).

`GET /api/view`:
- image ext → served inline with its `image/*` type;
- known-text ext **or** sniffed text → `text/plain; charset=utf-8`, inline,
  capped at 1 MiB (a giant log can't hang the tab); when capped it sets
  **`X-Sealpack-Truncated: 1`**;
- otherwise → **415** ("binary — not previewable").

Web edit flow: view → **Edit** swaps `<pre>` for `<textarea>` → **Save** POSTs the
buffer to `/api/put` → back to view + list refresh. **Editing is disabled when
`X-Sealpack-Truncated` is set** — otherwise saving would persist the truncated
copy and destroy the file. Images are view-only.

---

## 10. Runtime integration (noqi-vision-runtime)

sealpack is a **git submodule** of that repo (`third_party/sealpack`). Details
live there, but the contract sealpack must not break:

- `Pack::get(path, &blob)` returns raw bytes → the runtime's `ModelBase::Load`
  loads models from memory (`Runner::LoadMem`), no plaintext on disk.
- **ncnn is two files** (`.param` + `.bin`) stored as siblings; the runtime
  merges them into `[param_len:u64][param][bin]`. Gotcha it hit: ncnn's
  `load_model(mem)` is **zero-copy** — it keeps the pointer, so the caller must
  own the bin buffer for the model's lifetime (a temp blob → segfault). Not a
  sealpack bug, but sealpack's memory-load API is what surfaces it.
- The runtime also pulls **non-model** blobs now: `events/config.yaml`
  (broadcast-text templates) is bundled into every pack, and the runtime loads
  it via `Pack::get` → a `.spk` is self-contained (models + text).

---

## 11. Build & test

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build          # crypto/index/store/pack/crash/capi
```

The CLI binary is `build/sealpack` (target `sealpack-cli`,
`OUTPUT_NAME sealpack`). CI runs on ubuntu + macos with zero system deps.

---

## 12. Invariants & gotchas (read before you touch things)

- **Never hand-roll crypto.** All primitives go through monocypher. RNG is OS
  `getrandom`/`/dev/urandom`, never anything derived.
- **Android NDK (API < 28)**: the `getrandom` libc wrapper is undeclared → call
  `syscall(SYS_getrandom, …)` directly (`crypto.cpp`, fixed in `a084594`).
- **C ABI struct tag** can't be `sealpack` (collides with the C++ namespace) —
  it's `sealpack_handle`.
- **Format offsets are v2.** Don't hardcode superblock/data offsets; use the
  `store.cpp` constants. v1↔v2 are incompatible.
- **macOS durability** needs `F_FULLFSYNC`, not `fsync`.
- **Adding a CLI command** = edit `do_command` + `is_command` + `shell_help` +
  `usage` (four places).
- **`cat`/`edit`/web preview must refuse binary** via `looks_text` — dumping a
  model into a terminal or an editor is the failure mode we're guarding.
- **Web is localhost + token only.** Don't add a bind-address option that
  defaults to `0.0.0.0`, and don't render pack-controlled HTML/SVG.
- **Pack-controlled strings are untrusted in the web UI.** File/dir names and
  paths come from a `.spk` that may be hostile. The front-end builds every row
  with `textContent` + `addEventListener` closures — **never** string-interpolate
  a pack name into `innerHTML` or an inline `on*="…"` handler (that was a stored
  XSS). `esc()` is only for our own server messages.
- **The plaintext header is parsed before authentication.** `read_header_kdf`
  validates the Argon2 params (`nb_lanes` ≥ 1, `nb_passes` ≥ 1,
  `8·nb_lanes ≤ nb_blocks ≤ 4 GiB`) — a crafted `nb_lanes=0` divided-by-zero in
  monocypher (SIGFPE on `open`, pre-auth). Any new plaintext-header field must be
  range-checked there before it reaches crypto.
- **`edit` only writes back on a clean editor exit** (`WIFEXITED && WEXITSTATUS==0`).
  A crash or a deliberate `:cq` abort must not persist a truncated buffer.
- **The 8 key slots are load-bearing format, not a feature.** Single-password is
  the product decision; keep the array on disk.

---

## 13. Known gaps / TODO (for the maintenance session)

- Only slot 0 is used; multi-password was intentionally cut. If it ever comes
  back, `addkey`/`rmkey` + slot notes/labels were the sketched design.
- `web` has no auth beyond the session token and no TLS (localhost only by
  design). Revisit if it ever needs to bind non-loopback.
- `compact` is O(n) and single-shot; no incremental GC.
- No streaming API — `get` returns the whole blob in memory. Fine for models
  today; a multi-GB single blob would want chunking.
- Web edit has no concurrency guard: two tabs editing the same file → last-write
  wins (the pack mutex serializes the writes, but there's no conflict detection).
- `looks_text` is a heuristic; a UTF-16/BOM text file reads as binary. Add BOM
  sniffing if that comes up.
