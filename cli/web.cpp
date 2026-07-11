// `sealpack web <pack>` — a local file-manager UI over one pack.
//
// The C++ side holds the opened Pack (and the password-derived key); the browser
// only draws the UI and calls a localhost REST API. Bound to 127.0.0.1 only, and
// every /api/* call must carry the session token that's injected into the page,
// so another site (CSRF) or a stray same-host process can't drive it.

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <string>

#include "httplib.h"
#include "preview.hpp"
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
 .keys{border:1px solid var(--line);border-radius:9px;padding:14px 16px;margin-bottom:16px;background:#12151c}
 .keys h3{margin:0 0 4px;font-size:14px} .keys>.mut{font-size:12px}
 .keys section{margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
 .keys label{display:block;color:var(--mut);font-size:12px;margin:6px 0 2px}
 .keys input{width:200px} .keys .row{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end}
 .keys .msg{margin-top:8px;font-size:12px;min-height:15px}
 .keys .msg.ok{color:#5ac47d} .keys .msg.err{color:#e06c6c}
 .panel{position:fixed;top:0;right:0;width:min(560px,50vw);height:100vh;background:#12151c;border-left:1px solid var(--line);display:none;flex-direction:column;z-index:9;box-shadow:-8px 0 24px rgba(0,0,0,.35)}
 .panel.on{display:flex}
 .panel>header{border-bottom:1px solid var(--line)}
 .panel .path{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;color:var(--mut);word-break:break-all}
 .tools{display:flex;gap:6px;padding:8px 14px;border-bottom:1px solid var(--line);align-items:center}
 .tools .sp{margin-left:auto}
 .pbody{flex:1;overflow:auto;min-height:0}
 .pbody pre{margin:0;padding:14px 16px;white-space:pre-wrap;word-break:break-word;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace}
 .pbody textarea{display:block;width:100%;height:100%;border:0;outline:none;resize:none;background:#0d0f14;color:var(--fg);padding:14px 16px;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace}
 .pbody img{display:block;max-width:100%;margin:0 auto;background:#0a0c10}
 .pbody .note{padding:26px 16px;color:var(--mut);text-align:center}
 .msg{font-size:12px;padding:0 4px} .msg.ok{color:#5ac47d} .msg.err{color:#e06c6c}
 .x{cursor:pointer;background:none;border:none;color:var(--mut);font-size:18px}
</style></head>
<body>
<header><b>sealpack</b><span class="mut">file manager</span>
 <button onclick="toggleKeys()" style="margin-left:auto">&#128273; Password</button></header>
<main>
 <div class="keys" id="keys" style="display:none">
   <h3>&#128273; Change password</h3>
   <div class="row">
     <div><label>current password</label><input type="password" id="rk_old"></div>
     <div><label>new password</label><input type="password" id="rk_new1"></div>
     <div><label>confirm new password</label><input type="password" id="rk_new2"></div>
     <button class="acc" onclick="doRekey()">Change</button>
   </div>
   <div class="msg" id="rk_msg"></div>
 </div>
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
<div class="panel" id="panel">
 <header><b class="path" id="pv_name">preview</b>
   <button class="x" onclick="closePv()" style="margin-left:auto">&#10005;</button></header>
 <div class="tools" id="pv_tools"></div>
 <div class="pbody" id="pv_body"></div>
</div>
<script>
const TOKEN="%%TOKEN%%";
const H={"X-Sealpack-Token":TOKEN};
let cwd="";     // current folder: "" = root, "seg/" = inside seg
let ALL=[];     // full path list from the server
function fmtSize(n){if(n<1024)return n+" B";let u=["KB","MB","GB"],i=-1;do{n/=1024;i++}while(n>=1024&&i<2);return n.toFixed(1)+" "+u[i]}
function fmtTime(s){if(!s)return"";return new Date(s*1000).toLocaleString()}
async function refresh(){const r=await fetch("/api/list",{headers:H});ALL=await r.json();render()}
// Everything below builds the DOM with textContent + addEventListener rather
// than string-interpolated innerHTML: a pack's file/dir names are UNTRUSTED
// (the .spk may come from anyone), so they must never reach innerHTML or an
// inline on*="..." handler. textContent can't inject HTML; a closure can't
// inject JS. Keep it that way — see docs/DESIGN.md §8.
function td(cls){const e=document.createElement("td");if(cls)e.className=cls;return e}
function btn(text,title,fn,cls){const b=document.createElement("button");b.textContent=text;if(title)b.title=title;if(cls)b.className=cls;b.onclick=fn;return b}
function render(){
 const cb=document.getElementById("crumb");cb.textContent="";
 const root=document.createElement("a");root.textContent="root";root.onclick=()=>go("");cb.appendChild(root);
 let acc="";
 for(const seg of cwd.split("/").filter(Boolean)){
   acc+=seg+"/";const here=acc;
   const sep=document.createElement("span");sep.textContent=" / ";cb.appendChild(sep);
   const a=document.createElement("a");a.textContent=seg;a.onclick=()=>go(here);cb.appendChild(a);
 }
 const dirs=new Map(),files=[];
 for(const it of ALL){
   if(!it.path.startsWith(cwd))continue;
   const rest=it.path.slice(cwd.length);const i=rest.indexOf("/");
   if(i===-1)files.push({name:rest,size:it.size,mtime:it.mtime,path:it.path});
   else{const d=rest.slice(0,i);dirs.set(d,(dirs.get(d)||0)+1)}
 }
 const rows=document.getElementById("rows");rows.textContent="";
 for(const d of [...dirs.keys()].sort()){
   const cnt=dirs.get(d);const tr=document.createElement("tr");tr.className="dir";
   const t=td();const ico=document.createElement("span");ico.className="ico";ico.textContent=String.fromCodePoint(128193);
   const nm=document.createElement("span");nm.className="name";nm.textContent=d;nm.onclick=()=>go(cwd+d+"/");
   t.appendChild(ico);t.appendChild(nm);tr.appendChild(t);
   const sz=td("sz");sz.textContent=cnt+" item"+(cnt>1?"s":"");tr.appendChild(sz);
   tr.appendChild(td("mt"));tr.appendChild(td("act"));rows.appendChild(tr);
 }
 for(const f of files.sort((a,b)=>a.name<b.name?-1:1)){
   const tr=document.createElement("tr");
   const t=td();const ico=document.createElement("span");ico.className="ico";ico.textContent=String.fromCodePoint(128196);
   const nm=document.createElement("span");nm.className="name";nm.style.cursor="pointer";nm.title="preview";nm.textContent=f.name;nm.onclick=()=>pv(f.path);
   t.appendChild(ico);t.appendChild(nm);tr.appendChild(t);
   const sz=td("sz");sz.textContent=fmtSize(f.size);tr.appendChild(sz);
   const mt=td("mt");mt.textContent=fmtTime(f.mtime);tr.appendChild(mt);
   const act=td("act");
   act.appendChild(btn(String.fromCodePoint(128065),"preview",()=>pv(f.path)));
   act.appendChild(btn(String.fromCodePoint(8595),"download",()=>dl(f.path)));
   act.appendChild(btn("rename","",()=>ren(f.path,f.name)));
   act.appendChild(btn("copy","",()=>cp(f.path)));
   act.appendChild(btn(String.fromCodePoint(10005),"delete",()=>rm(f.path)));
   tr.appendChild(act);rows.appendChild(tr);
 }
 document.getElementById("empty").style.display=(dirs.size||files.length)?"none":"block";
}
function go(dir){cwd=dir;render()}
function dl(p){window.location="/api/get?t="+TOKEN+"&path="+encodeURIComponent(p)}
function esc(s){return s.replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]))}
// ---- right-side preview / edit panel ----
let pvPath=null,pvText=null,pvEditable=false,pvEditing=false;
function pvBody(){return document.getElementById("pv_body")}
function closePv(){document.getElementById("panel").classList.remove("on");pvPath=null;pvEditing=false;pvBody().innerHTML=""}
function pvTools(){
 const t=document.getElementById("pv_tools");
 if(!pvPath){t.innerHTML="";return}
 // Static buttons carry no pack data, so innerHTML is fine here; the download
 // button binds the untrusted pvPath via a closure (never string-interpolated).
 let h="";
 if(pvEditable&&!pvEditing)h+='<button class="acc" onclick="pvEdit()">&#9998; Edit</button>';
 if(pvEditing)h+='<button class="acc" onclick="pvSave()">Save</button><button onclick="pvView()">Cancel</button>';
 h+='<span class="sp"></span><span class="msg" id="pv_msg"></span>';
 t.innerHTML=h;
 t.appendChild(btn(String.fromCodePoint(8595),"download",()=>dl(pvPath)));
}
async function pv(p){
 pvPath=p;pvEditing=false;pvEditable=false;pvText=null;
 document.getElementById("pv_name").textContent=p;
 document.getElementById("panel").classList.add("on");
 const body=pvBody();body.innerHTML='<div class="note">loading&hellip;</div>';pvTools();
 const r=await fetch("/api/view?path="+encodeURIComponent(p),{headers:H});
 if(r.status===415){body.textContent="";const nt=document.createElement("div");nt.className="note";nt.appendChild(document.createTextNode("binary file — not previewable."));nt.appendChild(document.createElement("br"));nt.appendChild(document.createElement("br"));nt.appendChild(btn(String.fromCodePoint(8595)+" Download","",()=>dl(p),"acc"));body.appendChild(nt);pvTools();return}
 if(!r.ok){body.innerHTML='<div class="note">'+esc(await r.text())+'</div>';pvTools();return}
 const ct=r.headers.get("Content-Type")||"";
 if(ct.indexOf("image/")===0){const b=await r.blob();body.innerHTML="";const im=document.createElement("img");im.src=URL.createObjectURL(b);body.appendChild(im);pvTools();return}
 pvText=await r.text();
 pvEditable=r.headers.get("X-Sealpack-Truncated")!=="1";   // too big → view only
 pvView();
}
function pvView(){pvEditing=false;const b=pvBody();b.innerHTML='<pre></pre>';b.firstChild.textContent=pvText;pvTools()}
function pvEdit(){pvEditing=true;const b=pvBody();b.innerHTML='<textarea id="pv_ta" spellcheck="false"></textarea>';const ta=document.getElementById("pv_ta");ta.value=pvText;pvTools();ta.focus()}
async function pvSave(){
 const nt=document.getElementById("pv_ta").value;
 const r=await fetch("/api/put?path="+encodeURIComponent(pvPath),{method:"POST",headers:H,body:nt});
 const m=document.getElementById("pv_msg");
 if(r.ok){pvText=nt;pvView();const m2=document.getElementById("pv_msg");if(m2){m2.className="msg ok";m2.textContent="saved"}refresh()}
 else if(m){m.className="msg err";m.textContent="save failed: "+esc(await r.text())}
}
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!pvEditing)closePv()});
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
// ---- change password ----
function g(id){return document.getElementById(id)}
function setMsg(id,ok,text){const m=g(id);m.className="msg "+(ok?"ok":"err");m.textContent=text}
function toggleKeys(){const d=g("keys");d.style.display=d.style.display==="none"?"block":"none"}
function postForm(url,body){return fetch(url,{method:"POST",headers:Object.assign({"Content-Type":"application/x-www-form-urlencoded"},H),body:body})}
async function doRekey(){const o=g("rk_old").value,a=g("rk_new1").value,b=g("rk_new2").value;
 if(!a){setMsg("rk_msg",false,"new password is empty (that removes protection)");return}
 if(a!==b){setMsg("rk_msg",false,"the two new passwords don't match");return}
 const r=await postForm("/api/rekey","old="+encodeURIComponent(o)+"&new="+encodeURIComponent(a));
 if(r.ok){setMsg("rk_msg",true,"password changed — the old one no longer opens this pack");g("rk_old").value=g("rk_new1").value=g("rk_new2").value=""}
 else setMsg("rk_msg",false,await r.text())}
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

    // Inline preview: render human-readable blobs (text / images) in the browser
    // instead of downloading. Binary → 415 so the UI says "download instead".
    // Text is capped so a giant log can't hang the tab; images serve whole.
    srv.Get("/api/view", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        const std::string path = req.get_param_value("path");
        std::lock_guard<std::mutex> lk(mu);
        std::string data;
        if (!pack->get(path, &data)) { res.status = 404; res.set_content("not found", "text/plain"); return; }

        const char* m = sealpack_preview::mime_by_ext(path);
        if (sealpack_preview::is_image_mime(m)) {
            res.set_header("Content-Disposition", "inline");
            res.set_content(data, m);
            return;
        }
        if (m || sealpack_preview::looks_text(data)) {   // known-text ext or sniffed text
            const size_t kCap = 1u << 20;                // 1 MiB
            if (data.size() > kCap) {
                const std::string note = "\n\n[... truncated for preview — " +
                    std::to_string(data.size()) + " bytes total, download for the full file]";
                data.resize(kCap);
                data += note;
                res.set_header("X-Sealpack-Truncated", "1");   // UI: view-only, editing would truncate
            }
            res.set_header("Content-Disposition", "inline");
            res.set_content(data, m ? m : "text/plain; charset=utf-8");
            return;
        }
        res.status = 415;   // Unsupported Media Type
        res.set_content("binary — not previewable", "text/plain");
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

    // ---- change the password (rewrites an 88-byte slot; the data blobs never
    // move, so it's instant even on a multi-GB pack) ----
    srv.Post("/api/rekey", [&](const httplib::Request& req, httplib::Response& res) {
        if (!authed(req)) { res.status = 403; return; }
        std::lock_guard<std::mutex> lk(mu);
        // The page is already open with the pack — still require the current
        // password so a left-open tab can't silently change it.
        if (!pack->verify_password(req.get_param_value("old"))) {
            res.status = 403; res.set_content("current password is wrong", "text/plain"); return;
        }
        if (pack->rekey(req.get_param_value("new"))) res.set_content("ok", "text/plain");
        else { res.status = 400; res.set_content("rekey failed", "text/plain"); }
    });

    std::fprintf(stderr, "sealpack web: %s\n  open  http://%s:%d/?t=%s\n",
                 pack_path.c_str(), host.c_str(), port, token.c_str());
    if (!srv.listen(host, port)) {
        std::fprintf(stderr, "listen %s:%d failed\n", host.c_str(), port);
        return 1;
    }
    return 0;
}
