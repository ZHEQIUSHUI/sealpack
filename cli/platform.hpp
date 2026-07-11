#ifndef SEALPACK_CLI_PLATFORM_HPP
#define SEALPACK_CLI_PLATFORM_HPP

// Platform shim for the CLI's *interactive* bits. The core library is portable
// via src/os.hpp; this covers the console/editor pieces that genuinely differ:
// tty detection, no-echo password entry, and launching $EDITOR on a temp file.
//   POSIX   — termios echo-off, mkstemp(s), editor via system()+sys/wait.
//   Windows — SetConsoleMode echo-off, GetTempFileNameW, editor via _wsystem.
// Backends: platform_posix.cpp / platform_win32.cpp (picked in CMake).

#include <string>

namespace sealpack_cli {

bool stdin_is_tty();
bool stdout_is_tty();

// Prompt on stderr and read one line with echo disabled on a console (so the
// password isn't shown or left in scrollback). On a pipe it just reads a line —
// keeps scripting/CI working.
std::string read_password(const char* prompt);

// Decrypted `data` → a private temp file (kept with `name_hint`'s extension so
// the editor gets the right syntax mode) → $VISUAL/$EDITOR (default `vi` on
// POSIX, `notepad` on Windows) → read back into *out. Returns true ONLY on a
// clean editor exit; a crash / abort leaves *out untouched and returns false.
bool edit_in_editor(const std::string& name_hint, const std::string& data,
                    std::string* out);

}  // namespace sealpack_cli

#endif  // SEALPACK_CLI_PLATFORM_HPP
