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

// Embedded front-end — a folder-navigating file manager. %%TOKEN%% is replaced
// per-server-start. /api/list returns every path; the browser groups them by
// the current folder (subfolders you click into + files here), with a
// breadcrumb, so it behaves like a real file manager rather than a flat list.
const char* kIndexHtml = R"HTML(<!doctype html>
<html><head><meta charset="utf-8"><title>sealpack</title>
<style>
 :root{--bg:#0f1115;--fg:#e6e6e6;--mut:#9aa4b2;--acc:#4f8cff;--line:#232833;--dir:#e2b340}
 *{box-sizing:border-box}
 body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
 header{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:baseline}
 header b{font-size:15px} header .mut{color:var(--mut)}
 main{padding:14px 18px}
 .crumb{margin-bottom:12px}
 .crumb a{color:var(--acc);cursor:pointer;text-decoration:none} .crumb a:hover{text-decoration:underline}
 .crumb span{color:var(--mut)}
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
 .ico{display:inline-block;width:20px}
 .name{cursor:default}
 .dir .name{cursor:pointer;color:var(--dir)} .dir .name:hover{text-decoration:underline}
 .empty{color:var(--mut);padding:30px 0;text-align:center}
</style></head>
<body>
<header><b>sealpack</b><span class="mut">file manager</span></header>
<main>
 <div class="crumb" id="crumb"></div>
 <div class="up">
   <input type="file" id="file">
   <input type="text" id="dest" placeholder="name in this folder (optional)" size="26">
   <button class="acc" onclick="upload()">Upload here</button>
   <button onclick="refresh()">Refresh</button>
 </div>
 <table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
 <tbody id="rows"></tbody></table>
 <div class="empty" id="empty" style="display:none">empty folder</div>
</main>
<script>
const TOKEN="%%TOKEN%%";
const H={"X-Sealpack-Token":TOKEN};
let cwd="";     // current folder: "" = root, "seg/" = inside seg
let ALL=[];     // full path list from the server
function fmtSize(n){if(n<1024)return n+" B";let u=["KB","MB","GB"],i=-1;do{n/=1024;i++}while(n>=1024&&i<2);return n.toFixed(1)+" "+u[i]}
function fmtTime(s){if(!s)return"";return new Date(s*1000).toLocaleString()}
async function refresh(){const r=await fetch("/api/list",{headers:H});ALL=await r.json();render()}
function render(){
 const cb=document.getElementById("crumb");
 let html='<a onclick="go(String())">root</a>';let acc="";
 for(const seg of cwd.split("/").filter(Boolean)){acc+=seg+"/";html+=' <span>/</span> <a onclick="go(\''+acc+'\')">'+seg+'</a>'}
 cb.innerHTML=html;
 const dirs=new Map(),files=[];
 for(const it of ALL){
   if(!it.path.startsWith(cwd))continue;
   const rest=it.path.slice(cwd.length);const i=rest.indexOf("/");
   if(i===-1)files.push({name:rest,size:it.size,mtime:it.mtime,path:it.path});
   else{const d=rest.slice(0,i);dirs.set(d,(dirs.get(d)||0)+1)}
 }
 const rows=document.getElementById("rows");rows.innerHTML="";
 for(const [d,cnt] of [...dirs.keys()].sort().map(k=>[k,dirs.get(k)])){
   const tr=document.createElement("tr");tr.className="dir";
   tr.innerHTML='<td><span class="ico">&#128193;</span><span class="name" onclick="go(\''+cwd+d+'/\')">'+d+'</span></td>'+
     '<td class="sz">'+cnt+' item'+(cnt>1?'s':'')+'</td><td class="mt"></td><td class="act"></td>';
   rows.appendChild(tr);
 }
 for(const f of files.sort((a,b)=>a.name<b.name?-1:1)){
   const tr=document.createElement("tr");
   tr.innerHTML='<td><span class="ico">&#128196;</span><span class="name">'+f.name+'</span></td>'+
     '<td class="sz">'+fmtSize(f.size)+'</td><td class="mt">'+fmtTime(f.mtime)+'</td>'+
     '<td class="act"><button onclick="dl(\''+f.path+'\')">&#8595;</button>'+
     '<button onclick="ren(\''+f.path+'\',\''+f.name+'\')">rename</button>'+
     '<button onclick="cp(\''+f.path+'\')">copy</button>'+
     '<button onclick="rm(\''+f.path+'\')">&#10005;</button></td>';
   rows.appendChild(tr);
 }
 document.getElementById("empty").style.display=(dirs.size||files.length)?"none":"block";
}
function go(dir){cwd=dir;render()}
function dl(p){window.location="/api/get?t="+TOKEN+"&path="+encodeURIComponent(p)}
async function upload(){
 const f=document.getElementById("file").files[0];let name=document.getElementById("dest").value.trim();
 if(!f){alert("pick a file first");return}
 if(!name)name=f.name;
 const buf=await f.arrayBuffer();
 const r=await fetch("/api/put?path="+encodeURIComponent(cwd+name),{method:"POST",headers:H,body:buf});
 if(!r.ok)alert("upload failed: "+await r.text());
 else{document.getElementById("dest").value="";document.getElementById("file").value="";refresh()}
}
async function post(url){const r=await fetch(url,{method:"POST",headers:H});if(!r.ok)alert(await r.text());return r.ok}
async function rm(p){if(confirm("delete "+p+" ?"))if(await post("/api/del?path="+encodeURIComponent(p)))refresh()}
async function ren(p,name){const t=prompt("rename to (in this folder):",name);if(t&&t!==name)if(await post("/api/move?from="+encodeURIComponent(p)+"&to="+encodeURIComponent(cwd+t)))refresh()}
async function cp(p){const t=prompt("copy to (full path):",p);if(t&&t!==p)if(await post("/api/copy?from="+encodeURIComponent(p)+"&to="+encodeURIComponent(t)))refresh()}
refresh();
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
