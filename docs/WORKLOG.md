# sealpack — worklog

Chronological record of what was built and *why* (and where the direction
changed). Newest first. Pairs with `docs/DESIGN.md` (the current-state
reference). Commit hashes are on `ZHEQIUSHUI/sealpack`.

---

## 2026-07-11 — cross-platform: os:: seam + Windows core-library backend

Branch `feat/cross-platform` (stacked on the hardening branch). macOS/Linux were
already supported; this adds **Windows for the core library**.

- **`refactor(core)` — the `os::` seam.** Pulled every OS-specific file call the
  core made (`open`/`pread`/`pwrite`/sync/`rename`/`unlink`/size + wall-clock)
  out of store.cpp/pack.cpp into `src/os.hpp`, implemented by `os_posix.cpp`.
  Behavior-preserving — the 6 ctests are the regression. store.cpp already had
  the I/O funnelled into `pread_all`/`pwrite_all`/`durable_sync`, so the seam was
  half-there. Bonus: all opens now `O_CLOEXEC` (fixes the `web`-mode fd leak into
  spawned editors — was flagged in the same review pass).
- **`feat(win32)` — `os_win32.cpp` + CI.** Win32 backend: `CreateFileW`,
  `ReadFile`/`WriteFile` with `OVERLAPPED` (positional I/O, the pread/pwrite
  analog), `FlushFileBuffers` (durability barrier), `MoveFileExW` with
  `REPLACE_EXISTING|WRITE_THROUGH` (atomic replace for `compact`). RNG →
  `BCryptGenRandom` in crypto.cpp. CMake selects the backend by `WIN32` and links
  `bcrypt`; CI matrix gains `windows-latest` (with `--config Release`).
- **Validation without a Windows box.** Cross-compiled the core + Win32 backend
  with mingw-w64 (zero warnings) and ran **all 6 core test suites under wine64 —
  all pass**, including crash-recovery and the crafted-header regression. That
  exercises the real Win32 file I/O + BCryptGenRandom. `windows-latest` in CI is
  the real-MSVC confirmation (mingw ≠ MSVC, so CI still matters).
- **Scope call:** the CLI/web stays POSIX-only this round (termios/`mkstemp`/
  editor-spawn); on Windows only the library builds. The library is what the
  runtime embeds via the C ABI, so that's the portability that matters most. CLI
  Windows port is the tracked next step (DESIGN §13).

---

## 2026-07-11 — hardening: untrusted-pack DoS, web XSS, edit write-back

One PR (`harden/untrusted-pack-and-web-xss`) fixing three issues found in a
code-review pass. Threat model: a `.spk` is a *distributed* artifact, so
"someone hands you a hostile pack" is in scope.

- **crafted KDF params → SIGFPE on open (pre-auth).** The plaintext header's
  Argon2 params reach `derive_key` *before* the password/MAC is checked. A
  `nb_lanes=0` divides-by-zero inside monocypher's `crypto_argon2`
  (`monocypher.c:752`) → the process crashes on open — including any host that
  embeds sealpack via the C API (e.g. the runtime loading a `.spk`). Fix:
  `read_header_kdf` now range-checks the params and `open` returns nullptr
  cleanly. Regression: 4 crafted-header cases in `test_crash`.
- **stored XSS in `sealpack web`.** `render()` string-interpolated pack file/dir
  names into `innerHTML` and into `onclick` JS-string literals, so a pack with a
  name like `<img src=x onerror=…>.txt` ran arbitrary JS in a same-origin page
  that holds the API token. Rewrote the front-end row/crumb/preview construction
  to `textContent` + `addEventListener` closures (no interpolation reaches an
  HTML/JS sink). Verified the payload never lands in any `innerHTML`.
- **`edit` wrote back on a failed editor.** `system() != -1` only catches
  spawn failure; a crashed editor or a `:cq` abort (non-zero exit) still got
  its temp file read back and committed — persisting a possibly-truncated
  buffer. Now gated on `WIFEXITED && WEXITSTATUS==0`.

Note for later: the `web` layer still has **no automated test target** (ctest
covers core + capi only), so the XSS fix rests on review + a manual smoke test.
A headless-browser test would be the way to lock it down.

---

## 2026-07-11 — human-readable read/edit (`cat` + `edit`, web preview + edit)

- **`60d85bd` cat + web inline preview.** Added `cli/preview.hpp` (shared
  `looks_text` + `mime_by_ext`), `cat <path>` (print text, refuse binary), and
  `GET /api/view` (text/image inline, binary → 415) with a preview panel in the
  web UI. Motivation: a `.spk` now carries small config/text files (see the
  runtime's `events/config.yaml`), so you want to *read* them without extracting.
  Security call: `html/svg/js/css` are served as `text/plain` (show source, don't
  execute) because the web UI is same-origin with the token.
- **`094bb90` edit (vi) + web edit panel.** `edit <path>` opens the blob in
  `$VISUAL`/`$EDITOR` (default vi) via a temp file and saves back on change.
  Web preview became a **right-docked panel** (user asked for "click a file →
  text box on the right → Edit to modify"); Edit swaps to a `<textarea>`, Save
  POSTs to `/api/put`. Guard: files truncated by the 1 MiB preview cap
  (`X-Sealpack-Truncated`) are **view-only** so a save can't persist the
  truncated copy.
- Testing note for later: `edit` needs a TTY, so headless tests drive it through
  a pty — `printf 'pw\n' | script -qec "EDITOR=/tmp/fake.sh sealpack edit …" /dev/null`
  (one-shot mode still prompts for the password on a TTY, so feed it via the pty
  stdin). Verified round-trip updates the encrypted pack (`cat` confirms), no-op
  edits report `unchanged`, binaries are refused.

---

## 2026-07-10 — Android build fix

- **`a084594` getrandom via syscall.** The `getrandom()` libc wrapper is
  undeclared on Android NDK API < 28 → cross-compile failed. Switched to
  `syscall(SYS_getrandom, …)` directly. This is what lets the runtime build
  sealpack into an Android `.so`.

---

## 2026-07-09 — the big day: v2 key-wrapping, CLI shell, web UI, submodule

Ordered as it happened:

- **`dd3686a` initial sealpack.** Encrypted single-file content-addressed store.
  Rationale for building rather than reusing: leveldb had the features but a
  fragmented LSM layout and no encryption → an "encrypted git packfile" fit
  better. Four pillars: single file, AEAD encryption (monocypher, no hand-rolled
  crypto), BLAKE2b content-addressed dedup, double-superblock crash safety.
- **`e2e2792` cross-platform durable_sync.** macOS CI caught that `fdatasync`
  doesn't exist there and `fsync` doesn't hit the platter → `F_FULLFSYNC` on
  macOS, `fdatasync` on Linux.
- **`adafd5d` + `860e92e` web UI.** `sealpack web` — localhost file manager
  (cpp-httplib vendored, REST + embedded vanilla front-end, session token for
  CSRF), then folder-tree navigation + breadcrumb instead of a flat list. The
  web layer lives only in the CLI; the core library never touches HTTP.
- **`d127114` submodule-friendly CMake.** `CMAKE_CURRENT_SOURCE_DIR` so the repo
  works when embedded as `third_party/sealpack` in the runtime.
- **`1da1c5e` + `afad023` key-wrapping (v2 format).** Random master key encrypts
  the data; the password only wraps the master key into an 8-slot LUKS-style
  array. Payoff: **rekey rewrites one 88-byte slot, the data region never moves**
  → instant on multi-GB packs. This changed the on-disk format (v1 → v2, all
  offsets moved) — incompatible, no in-place upgrade.
- **`7c502d3` interactive shell.** `sealpack <pack>` prompts for the password
  once and drops into a mini shell reusing the open pack — one Argon2 per
  session, password never in argv/history. (User disliked the
  `$SEALPACK_PASSWORD` env-var-per-command flow; env var kept only for non-TTY
  scripting.)
- **`a27f451` human-readable sizes.** `ls`/`stat` show KB/MB/GB, not raw bytes.
- **`0852c1d` cut multi-password → single password.** The key-wrapping work had
  briefly grown `addkey`/`rmkey` for multiple passwords. Product decision:
  shipping model packs never needs more than one password, so it was cut back to
  single-password + `rekey`. **The 8-slot array stayed on disk** (only slot 0
  used) so the format didn't churn again — that's why the format still looks
  multi-slot.

---

## Direction changes worth remembering

- **Multi-password → single.** Built, then deliberately removed. Don't
  reintroduce `addkey`/`rmkey` without a real use case; the slots are kept only
  as format ballast.
- **Env-var password → interactive shell.** `$SEALPACK_PASSWORD` is the
  scripting fallback, not the primary UX.
- **Preview modal → right-docked panel.** Per explicit user preference; edit
  lives in the panel, not a popup.
- **`.spk` grew from models-only to models + text.** The preview/edit and `cat`
  features exist because packs now hold human-readable config too.

## Naming convention

`.spk` = the encrypted pack **file**. "sealpack" (no suffix) = this repo / the
library / the CLI. Keep them distinct in docs and messages.
