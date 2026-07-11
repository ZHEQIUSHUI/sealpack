#pragma once

// Shared helpers for the human-readable views (`cat` in the CLI, inline
// preview in the web UI). Deciding text-vs-binary happens here in one place so
// both surfaces agree on what's safe to render into a terminal / browser.

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>

namespace sealpack_preview {

// Heuristic: is this blob printable text (so we can dump it), or binary (a
// model / image / archive we must not spew)? Scans the head only.
//   - a NUL byte anywhere in the head → binary (models, most containers)
//   - >5% C0 control chars (excluding tab/newline/CR) → binary
//   - bytes >= 0x80 are NOT counted — UTF-8 multibyte text stays "text"
inline bool looks_text(const std::string& s) {
    if (s.empty()) return true;
    const size_t n = std::min<size_t>(s.size(), 8192);
    size_t suspicious = 0;
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0) return false;
        if (c == '\t' || c == '\n' || c == '\r') continue;
        if (c < 0x20 || c == 0x7f) ++suspicious;
    }
    return suspicious * 100 < n * 5;
}

// MIME for inline preview by extension, or nullptr if unknown (caller then
// falls back to looks_text). Only image/* types are meant to be *rendered*;
// html/svg deliberately map to text/plain so the browser shows their source
// instead of executing them (the pack could hold a hostile .svg/.html and the
// web UI is same-origin with the token).
inline const char* mime_by_ext(const std::string& path) {
    const auto dot = path.find_last_of('.');
    if (dot == std::string::npos) return nullptr;
    std::string e = path.substr(dot + 1);
    for (char& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (e == "txt" || e == "log" || e == "md" || e == "markdown" || e == "csv" ||
        e == "tsv" || e == "ini" || e == "cfg" || e == "conf" || e == "toml" ||
        e == "yaml" || e == "yml" || e == "properties")
        return "text/plain; charset=utf-8";
    if (e == "json") return "application/json; charset=utf-8";
    if (e == "xml")  return "text/xml; charset=utf-8";
    // Show source, do NOT render (XSS-safe):
    if (e == "html" || e == "htm" || e == "svg" || e == "js" || e == "css")
        return "text/plain; charset=utf-8";
    // Safe to render inline:
    if (e == "png")  return "image/png";
    if (e == "jpg" || e == "jpeg") return "image/jpeg";
    if (e == "gif")  return "image/gif";
    if (e == "webp") return "image/webp";
    if (e == "bmp")  return "image/bmp";
    return nullptr;
}

inline bool is_image_mime(const char* m) {
    return m && std::strncmp(m, "image/", 6) == 0;
}

}  // namespace sealpack_preview
