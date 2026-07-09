// `sealpack web <pack>` — a local file-manager UI over one pack.
//
// The C++ side holds the opened Pack (and the password-derived key); the browser
// only draws the UI and calls a localhost REST API. Bound to 127.0.0.1 only, and
// every /api/* call must carry the session token that's injected into the page,
// so another site (CSRF) or a stray same-host process can't drive it.

#include <cstdio>
#include <fstream>
#include <mutex>
#include <string>

#include "httplib.h"
#include "sealpack.hpp"

using sealpack::Pack;

namespace {

std::string gen_token() {
    unsigned char b[16] = {0};
    std::ifstream u("/dev/urandom", std::ios::binary);
    u.read(reinterpret_cast<char*>(b), sizeof b);
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += hex[c >> 4]; s += hex[c & 0xf]; }
    return s;
}

std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

// Embedded front-end. %%TOKEN%% is replaced per-server-start.
const char* kIndexHtml = R"HTML(<!doctype html>
<html><head><meta charset="utf-8"><title>sealpack</title>
<style>
 :root{--bg:#0f1115;--fg:#e6e6e6;--mut:#9aa4b2;--acc:#4f8cff;--line:#232833}
 *{box-sizing:border-box}
 body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
 header{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center}
 header b{font-size:15px} header .mut{color:var(--mut)}
 main{padding:14px 18px}
 .up{display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
 input,button{font:inherit;color:var(--fg);background:#171a21;border:1px solid var(--line);border-radius:7px;padding:7px 10px}
 button{cursor:pointer} button:hover{border-color:var(--acc)}
 button.acc{background:var(--acc);border-color:var(--acc);color:#fff}
 table{width:100%;border-collapse:collapse}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
 th{color:var(--mut);font-weight:500;font-size:12px}
 td.sz,td.mt{color:var(--mut);white-space:nowrap}
 td.act{text-align:right;white-space:nowrap}
 td.act button{padding:4px 8px;margin-left:4px}
 tr:hover td{background:#141821}
 .path{font-family:ui-monospace,monospace}
 .empty{color:var(--mut);padding:30px 0;text-align:center}
</style></head>
<body>
<header><b>sealpack</b><span class="mut" id="pack"></span></header>
<main>
 <div class="up">
   <input type="file" id="file">
   <input type="text" id="dest" placeholder="path in pack, e.g. yolo/v2.axmodel" size="34">
   <button class="acc" onclick="upload()">Upload</button>
 </div>
 <table><thead><tr><th>Path</th><th>Size</th><th>Modified</th><th></th></tr></thead>
 <tbody id="rows"></tbody></table>
 <div class="empty" id="empty" style="display:none">empty pack — upload a file</div>
</main>
<script>
const TOKEN="%%TOKEN%%";
const H={"X-Sealpack-Token":TOKEN};
function fmtSize(n){if(n<1024)return n+" B";let u=["KB","MB","GB"],i=-1;do{n/=1024;i++}while(n>=1024&&i<2);return n.toFixed(1)+" "+u[i]}
function fmtTime(s){if(!s)return"";return new Date(s*1000).toLocaleString()}
async function load(){
 const r=await fetch("/api/list",{headers:H});const items=await r.json();
 const rows=document.getElementById("rows");rows.innerHTML="";
 document.getElementById("empty").style.display=items.length?"none":"block";
 for(const it of items){
   const tr=document.createElement("tr");
   tr.innerHTML=`<td class="path">${it.path}</td><td class="sz">${fmtSize(it.size)}</td><td class="mt">${fmtTime(it.mtime)}</td>`+
     `<td class="act"><button onclick="dl('${it.path}')">↓</button>`+
     `<button onclick="ren('${it.path}')">rename</button>`+
     `<button onclick="cp('${it.path}')">copy</button>`+
     `<button onclick="rm('${it.path}')">✕</button></td>`;
   rows.appendChild(tr);
 }
}
function dl(p){window.location="/api/get?t="+TOKEN+"&path="+encodeURIComponent(p)}
async function upload(){
 const f=document.getElementById("file").files[0];const dest=document.getElementById("dest").value.trim();
 if(!f||!dest){alert("pick a file and a destination path");return}
 const buf=await f.arrayBuffer();
 const r=await fetch("/api/put?path="+encodeURIComponent(dest),{method:"POST",headers:H,body:buf});
 if(!r.ok){alert("upload failed: "+await r.text())}else{document.getElementById("dest").value="";load()}
}
async function post(url){const r=await fetch(url,{method:"POST",headers:H});if(!r.ok)alert(await r.text());return r.ok}
async function rm(p){if(confirm("delete "+p+"?"))if(await post("/api/del?path="+encodeURIComponent(p)))load()}
async function ren(p){const t=prompt("rename to:",p);if(t&&t!==p)if(await post("/api/move?from="+encodeURIComponent(p)+"&to="+encodeURIComponent(t)))load()}
async function cp(p){const t=prompt("copy to:",p);if(t&&t!==p)if(await post("/api/copy?from="+encodeURIComponent(p)+"&to="+encodeURIComponent(t)))load()}
load();
</script></body></html>)HTML";

}  // namespace

int run_web(Pack* pack, const std::string& pack_path,
            const std::string& host, int port) {
    std::mutex mu;
    const std::string token = gen_token();
    httplib::Server srv;

    auto authed = [&](const httplib::Request& req) {
        return req.get_header_value("X-Sealpack-Token") == token ||
               req.get_param_value("t") == token;
    };

    srv.Get("/", [&](const httplib::Request&, httplib::Response& res) {
        std::string html = kIndexHtml;
        const std::string ph = "%%TOKEN%%";
        auto pos = html.find(ph);
        if (pos != std::string::npos) html.replace(pos, ph.size(), token);
        res.set_content(html, "text/html");
    });

    srv.Get("/api/list", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        std::lock_guard<std::mutex> lk(mu);
        std::string j = "[";
        const auto ls = pack->list();
        for (size_t i = 0; i < ls.size(); ++i) {
            if (i) j += ",";
            j += "{\"path\":\"" + json_escape(ls[i].path) + "\",\"size\":" +
                 std::to_string(ls[i].size) + ",\"mtime\":" + std::to_string(ls[i].mtime) + "}";
        }
        j += "]";
        res.set_content(j, "application/json");
    });

    srv.Get("/api/get", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        const std::string path = req.get_param_value("path");
        std::lock_guard<std::mutex> lk(mu);
        std::string data;
        if (!pack->get(path, &data)) { res.status = 404; res.set_content("not found", "text/plain"); return; }
        const auto slash = path.find_last_of('/');
        const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
        res.set_header("Content-Disposition", "attachment; filename=\"" + name + "\"");
        res.set_content(data, "application/octet-stream");
    });

    auto commit_reply = [&](bool ok, httplib::Response& res) {
        if (ok && pack->commit()) { res.set_content("ok", "text/plain"); }
        else { res.status = 400; res.set_content("failed", "text/plain"); }
    };

    srv.Post("/api/put", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        const std::string path = req.get_param_value("path");
        std::lock_guard<std::mutex> lk(mu);
        commit_reply(pack->put(path, req.body.data(), req.body.size()), res);
    });
    srv.Post("/api/del", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        std::lock_guard<std::mutex> lk(mu);
        commit_reply(pack->del(req.get_param_value("path")), res);
    });
    srv.Post("/api/move", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        std::lock_guard<std::mutex> lk(mu);
        commit_reply(pack->move(req.get_param_value("from"), req.get_param_value("to")), res);
    });
    srv.Post("/api/copy", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        std::lock_guard<std::mutex> lk(mu);
        commit_reply(pack->copy(req.get_param_value("from"), req.get_param_value("to")), res);
    });

    std::fprintf(stderr, "sealpack web: %s\n  open  http://%s:%d/?t=%s\n",
                 pack_path.c_str(), host.c_str(), port, token.c_str());
    if (!srv.listen(host, port)) {
        std::fprintf(stderr, "listen %s:%d failed\n", host.c_str(), port);
        return 1;
    }
    return 0;
}
