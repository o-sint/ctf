/* ============ CONFIG ============ */
const API = "/api"; // match index.html
/* ================================ */
const $=(s)=>document.querySelector(s);
/* storage that never throws (Safari private mode / blocked storage) — falls back to memory */
function makeStore(kind){
  const mem={}; let ok=true;
  try{ const s=window[kind]; s.setItem("__t","1"); s.removeItem("__t"); }catch(e){ ok=false; }
  return {
    get:(k)=>{ try{ return ok?window[kind].getItem(k):(mem[k]??null); }catch(e){ return mem[k]??null; } },
    set:(k,v)=>{ try{ if(ok) window[kind].setItem(k,v); else mem[k]=v; }catch(e){ mem[k]=v; } },
    del:(k)=>{ try{ if(ok) window[kind].removeItem(k); }catch(e){} delete mem[k]; },
  };
}
const session=makeStore("sessionStorage"); // tab-scoped; cleared when the tab closes
let TOKEN=session.get("ctf_admin")||"";

async function api(path,opts={},auth=true){
  const h={"Content-Type":"application/json",...(opts.headers||{})};
  if(auth&&TOKEN) h["Authorization"]="Bearer "+TOKEN;
  let r;
  try{ r=await fetch(API+path,{...opts,headers:h}); }
  catch(e){ const er=new Error("network error"); er.status=0; er.data={}; throw er; }
  const j=await r.json().catch(()=>({error:"bad response"}));
  if(!r.ok){ const er=new Error(j.error||("HTTP "+r.status)); er.status=r.status; er.data=j; throw er; }
  return j;
}
const genToken=()=>[...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,"0")).join("");
function gen(inSel,msgSel){ // 256 random bits, shown once so it can go straight into a password manager
  const i=$(inSel); i.value=genToken(); i.type="text";
  $(msgSel).className="msg ok"; $(msgSel).textContent="Generated. Copy it into your password manager now.";
}
const toLocal=(ms)=>{ if(!ms)return""; const d=new Date(ms); const p=n=>String(n).padStart(2,"0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; };
const fromLocal=(s)=> s?new Date(s).getTime():0;

async function unlock(){
  try{ await api("/admin/users"); session.set("ctf_admin",TOKEN); $("#gate").style.display="none"; $("#app").style.display="block"; loadAll(); }
  catch(e){ TOKEN=""; session.del("ctf_admin"); $("#gate").style.display=""; $("#app").style.display="none"; $("#gateMsg").className="msg bad"; $("#gateMsg").textContent="Rejected: "+e.message; }
}
$("#lockBtn").onclick=()=>{ TOKEN=""; session.del("ctf_admin"); $("#tok").value=""; $("#app").style.display="none"; $("#gate").style.display=""; };
$("#bootGen").onclick=()=>gen("#bootTok","#bootMsg");
$("#genTok").onclick=()=>gen("#newTok","#dzMsg");
$("#gateBtn").onclick=()=>{ TOKEN=$("#tok").value.trim(); unlock(); };
$("#tok").onkeydown=e=>{if(e.key==="Enter"){TOKEN=$("#tok").value.trim();unlock();}};
$("#bootBtn").onclick=async()=>{
  const boot=$("#boot").value.trim(), nt=$("#bootTok").value.trim();
  if(nt.length<20){ $("#bootMsg").className="msg bad"; $("#bootMsg").textContent="Token must be at least 20 chars (use Generate)."; return; }
  try{
    await fetch(API+"/admin/rotate-token",{method:"POST",headers:{"Content-Type":"application/json","X-Bootstrap-Key":boot},body:JSON.stringify({new_token:nt})})
      .then(async r=>{const j=await r.json();if(!r.ok)throw new Error(j.error);});
    $("#bootMsg").className="msg ok"; $("#bootMsg").textContent="Token set. Unlock above with it.";
    TOKEN=nt; $("#tok").value=nt;
  }catch(e){ $("#bootMsg").className="msg bad"; $("#bootMsg").textContent=e.message; }
};

async function loadAll(){
  loadState().catch(()=>{}); loadChallenges().catch(()=>{}); loadUsers().catch(()=>{}); loadJoinCode();
  // countdown ticks locally; /state is re-read once a minute and only while the tab is visible
  if(!loadAll.started){ loadAll.started=true;
    setInterval(paintEvNow,1000);
    setInterval(()=>{ if(!document.hidden) loadState().catch(()=>{}); },60000); }
}
async function loadJoinCode(){
  try{ const j=await api("/admin/join-code"); $("#joinCode").value=j.code||""; }catch(e){}
}
$("#joinCodeSave").onclick=async()=>{
  try{
    const j=await api("/admin/join-code",{method:"POST",body:JSON.stringify({code:$("#joinCode").value.trim()})});
    $("#joinCodeMsg").className="msg ok";
    $("#joinCodeMsg").textContent=j.code?`Saved. Players now need "${j.code}" to join.`:"Saved. Anyone can join (no code required).";
  }catch(e){ $("#joinCodeMsg").className="msg bad"; $("#joinCodeMsg").textContent=e.message; }
};
const fmt=(ms)=>{ if(ms<0)ms=0; const s=Math.floor(ms/1000); const h=Math.floor(s/3600),m=Math.floor(s%3600/60),ss=s%60;
  return [h,m,ss].map(x=>String(x).padStart(2,"0")).join(":"); };
let EV_FORM_LOADED=false, ADM_STATE=null, ADM_OFFSET=0;
function paintEvNow(){
  const s=ADM_STATE; if(!s) return;
  const t=Date.now()+ADM_OFFSET;
  const p=!s.start||!s.end?"unset":t<s.start?"pre":t>s.end?"post":"live";
  if(p==="pre") $("#evNow").textContent="starts in "+fmt(s.start-t);
  else if(p==="live") $("#evNow").textContent="ends in "+fmt(s.end-t);
  else if(p==="post") $("#evNow").textContent="ended";
  else $("#evNow").textContent="not scheduled";
}
async function loadState(){
  const s=await api("/state",{},false);
  if(!EV_FORM_LOADED){
    $("#evName").value=s.name||"";
    $("#evStart").value=toLocal(s.start);
    $("#evEnd").value=toLocal(s.end);
    EV_FORM_LOADED=true;
  }
  ADM_STATE=s; ADM_OFFSET=s.now-Date.now();
  paintEvNow();
}
$("#evSave").onclick=async()=>{
  try{ await api("/admin/event",{method:"POST",body:JSON.stringify({name:$("#evName").value,start:fromLocal($("#evStart").value),end:fromLocal($("#evEnd").value)})});
    $("#evMsg").className="msg ok"; $("#evMsg").textContent="Saved."; loadState(); }
  catch(e){ $("#evMsg").className="msg bad"; $("#evMsg").textContent=e.message; }
};

async function quickEvent(body,okText){
  try{ await api("/admin/event",{method:"POST",body:JSON.stringify(body)});
    $("#evMsg").className="msg ok"; $("#evMsg").textContent=okText;
    EV_FORM_LOADED=false; loadState().catch(()=>{}); }
  catch(e){ $("#evMsg").className="msg bad"; $("#evMsg").textContent=e.message; }
}
$("#evStartNow").onclick=()=>quickEvent({start:Math.floor(Date.now()/60000)*60000},"Start set to the current minute.");
$("#evEndNow").onclick=()=>{ if(confirm("End the event right now?")) quickEvent({end:Date.now()},"Event ended."); };

$("#bulkFile").onchange=(e)=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=()=>$("#bulk").value=r.result;r.readAsText(f);};
$("#bulkBtn").onclick=async()=>{
  if(!$("#bulk").value.trim()){$("#bulkMsg").className="msg bad";$("#bulkMsg").textContent="Choose a JSON file first.";return;}
  let data; try{data=JSON.parse($("#bulk").value);}catch(e){$("#bulkMsg").className="msg bad";$("#bulkMsg").textContent="Invalid JSON: "+e.message;return;}
  try{ const j=await api("/admin/challenges",{method:"POST",body:JSON.stringify(data)});
    $("#bulkMsg").className="msg ok"; $("#bulkMsg").textContent=`Upserted ${j.upserted}. Skipped: ${j.skipped.join(", ")||"none"}.`; loadChallenges(); }
  catch(e){ $("#bulkMsg").className="msg bad"; $("#bulkMsg").textContent=e.message; }
};
$("#bulkExport").onclick=async()=>{
  try{
    const j=await api("/admin/challenges");
    if(!j.challenges.length){ $("#bulkMsg").className="msg bad"; $("#bulkMsg").textContent="No challenges to export."; return; }
    download(slug($("#evName").value||"ctf")+"-challenges-backup.json", JSON.stringify(j.challenges,null,2), "application/json");
    $("#bulkMsg").className="msg ok"; $("#bulkMsg").textContent=`Downloaded ${j.challenges.length} challenge(s), including answers. Keep this file safe.`;
  }catch(e){ $("#bulkMsg").className="msg bad"; $("#bulkMsg").textContent=e.message; }
};

function genChallengeId(){
  const n=String(Math.floor(Math.random()*100000)).padStart(5,"0");
  return "c1-"+n;
}
$("#c_new").onclick=()=>{
  ["c_cat","c_title","c_prompt","c_hint","c_answers","c_sol"].forEach(id=>$("#"+id).value="");
  $("#c_id").value=genChallengeId();
  $("#c_initial").value=100; $("#c_min").value=50; $("#c_decay").value=5;
  $("#c_att").value=10; $("#c_hold").value=30; $("#c_hcost").value=0;
  $("#c_msg").className="msg dim"; $("#c_msg").textContent="New challenge. Fill in and Save.";
  $("#c_id").focus();
  window.scrollTo({top:$("#c_id").getBoundingClientRect().top+window.scrollY-80,behavior:"smooth"});
};
$("#c_save").onclick=async()=>{
  const obj={ id:$("#c_id").value.trim(), category:$("#c_cat").value.trim(), title:$("#c_title").value.trim(),
    prompt:$("#c_prompt").value, initial:+$("#c_initial").value, minimum:+$("#c_min").value, decay:+$("#c_decay").value,
    attempts_max:+$("#c_att").value, holdoff_ms:Math.round(+$("#c_hold").value*1000), hint:$("#c_hint").value, hint_cost:+$("#c_hcost").value,
    answers:$("#c_answers").value.split("\n").map(x=>x.trim()).filter(Boolean), solution:$("#c_sol").value };
  try{ const j=await api("/admin/challenges",{method:"POST",body:JSON.stringify([obj])});
    $("#c_msg").className="msg ok"; $("#c_msg").textContent = j.upserted?"Saved.":("Skipped: "+j.skipped.join(", ")); loadChallenges(); }
  catch(e){ $("#c_msg").className="msg bad"; $("#c_msg").textContent=e.message; }
};

async function loadChallenges(){
  const j=await api("/admin/challenges");
  $("#chCount").textContent=j.challenges.length+" challenge"+(j.challenges.length===1?"":"s");
  const tb=$("#chTbl tbody"); tb.innerHTML="";
  j.challenges.forEach(c=>{
    const tr=document.createElement("tr");
    const promptFull=c.prompt||"";
    tr.innerHTML=`<td><code>${esc(c.id)}</code></td><td>${esc(c.category)}</td><td>${esc(c.title)}</td>
      <td class="prompt-cell" title="${esc(promptFull)}">${esc(promptFull)}</td>
      <td class="pts">${c.initial}/${c.minimum}</td><td>${(c.answers||[]).length}</td>
      <td class="actions"><button class="iconbtn" title="Edit" data-e="${esc(c.id)}">✏️</button><button class="iconbtn danger" title="Delete" data-d="${esc(c.id)}">🗑</button></td>`;
    tb.appendChild(tr);
  });
  tb.querySelectorAll("[data-d]").forEach(b=>b.onclick=async()=>{ if(!confirm("Delete "+b.dataset.d+"?"))return;
    try{ await api("/admin/challenge/"+encodeURIComponent(b.dataset.d),{method:"DELETE"}); loadChallenges(); }catch(e){ alert(e.message); } });
  tb.querySelectorAll("[data-e]").forEach(b=>b.onclick=()=>editChallenge(j.challenges.find(x=>x.id===b.dataset.e)));
  loadIcons([...new Set(j.challenges.map(c=>c.category))].sort());
}

async function loadIcons(categories){
  const wrap=$("#iconRows");
  if(!categories.length){ wrap.innerHTML=`<div class="dim" style="font-size:12px">No challenges loaded yet — categories come from your challenge list.</div>`; return; }
  const j=await api("/admin/category-icons");
  wrap.innerHTML="";
  categories.forEach(cat=>{
    const key=cat.toUpperCase();
    const current=j.overrides[key]||j.defaults[key]||j.defaults._DEFAULT;
    const isOverridden=!!j.overrides[key];
    const row=document.createElement("div");
    row.className="row"; row.style.marginBottom="8px"; row.style.alignItems="center";
    row.innerHTML=`
      <img data-prev src="${esc(current)}" width="22" height="22" style="border-radius:4px;background:var(--panel2);flex:none"/>
      <span style="min-width:110px;font-family:var(--mono);font-size:12px">${esc(cat)}</span>
      <input type="text" data-in value="${esc(j.overrides[key]||"")}" placeholder="data:image/svg+xml;base64,... (blank = default)" style="flex:1;min-width:220px;font-size:12px"/>
      <a href="https://allsvgicons.com/search/?q=${encodeURIComponent(cat.split(" ")[0].toLowerCase())}" target="_blank" rel="noopener" style="font-size:12px;white-space:nowrap">browse ↗</a>
      <button data-save style="font-size:12px">Save</button>
      <span class="dim" data-tag style="font-size:11px">${isOverridden?"custom":"default"}</span>`;
    const img=row.querySelector("[data-prev]"), inp=row.querySelector("[data-in]"), tag=row.querySelector("[data-tag]");
    inp.oninput=()=>{ const v=inp.value.trim(); if(/^data:image\//i.test(v)||/^https:\/\//i.test(v)) img.src=v; }; // preview only real icon values (was: every keystroke hit img.src, firing junk requests)
    row.querySelector("[data-save]").onclick=async()=>{
      try{
        const r=await api("/admin/category-icons",{method:"POST",body:JSON.stringify({icons:{[cat]:inp.value.trim()}})});
        const now=r.overrides[key];
        img.src=now||j.defaults[key]||j.defaults._DEFAULT;
        tag.textContent=now?"custom":"default";
      }catch(e){ alert(e.message); }
    };
    wrap.appendChild(row);
  });
}
$("#iconReload").onclick=loadChallenges;

function editChallenge(c){
  $("#c_id").value=c.id;$("#c_cat").value=c.category;$("#c_title").value=c.title;$("#c_prompt").value=c.prompt||"";
  $("#c_initial").value=c.initial;$("#c_min").value=c.minimum;$("#c_decay").value=c.decay;
  $("#c_att").value=c.attempts_max;$("#c_hold").value=Math.round((c.holdoff_ms||0)/1000);$("#c_hcost").value=c.hint_cost;
  $("#c_hint").value=c.hint||"";$("#c_sol").value=c.solution||"";
  $("#c_answers").value=(c.answers||[]).join("\n"); $("#c_answers").placeholder="one accepted answer per line";
  $("#c_msg").className="msg dim"; $("#c_msg").textContent="Loaded "+c.id+". Edit and Save.";
  window.scrollTo({top:$("#c_id").getBoundingClientRect().top+window.scrollY-80,behavior:"smooth"});
}
$("#chReload").onclick=loadChallenges;
// In-page "type the word" confirmation (native prompt() can be suppressed by the browser and gave no feedback on a typo)
function armConfirm(o){
  const box=$(o.box), inp=$(o.input), go=$(o.go);
  const show=(v)=>{ box.style.display=v?"":"none"; if(v){ inp.value=""; go.disabled=true; inp.focus(); } };
  $(o.btn).onclick=()=>show(box.style.display==="none");
  $(o.cancel).onclick=()=>show(false);
  inp.oninput=()=>{ go.disabled=inp.value.trim().toUpperCase()!==o.word; };
  inp.onkeydown=(e)=>{ if(e.key==="Enter"&&!go.disabled) go.click(); if(e.key==="Escape") show(false); };
  go.onclick=async()=>{
    if(inp.value.trim().toUpperCase()!==o.word) return;
    go.disabled=true;
    try{ await o.run(); show(false); }
    catch(e){ const m=$(o.msg); m.className="msg bad"; m.textContent=e.message; go.disabled=false; }
  };
}
armConfirm({btn:"#chClear",box:"#chClearBox",input:"#chClearIn",go:"#chClearGo",cancel:"#chClearCancel",msg:"#chClearMsg",word:"DELETE ALL",
  run:async()=>{ const j=await api("/admin/challenges/clear",{method:"POST"}); await loadChallenges();
    const m=$("#chClearMsg"); m.className="msg ok"; m.textContent="Removed "+j.removed+" challenge"+(j.removed===1?"":"s")+"."; }});

async function loadUsers(){
  const j=await api("/admin/users");
  const tb=$("#uTbl"); tb.innerHTML="";
  j.users.forEach(u=>{
    const row=document.createElement("div");
    row.className="prow";
    row.innerHTML=`<span>${esc(u.name)}</span>
      <span class="row" style="gap:4px">
        <button class="iconbtn" title="Rename" data-r="${esc(u.uuid)}" data-n="${esc(u.name)}">✏️</button>
        <button class="iconbtn danger" title="Remove" data-x="${esc(u.uuid)}">🗑</button>
      </span>`;
    tb.appendChild(row);
  });
  tb.querySelectorAll("[data-r]").forEach(b=>b.onclick=async()=>{
    const nn=prompt("New name for "+b.dataset.n+":",b.dataset.n); if(!nn)return;
    try{ await api("/admin/user/rename",{method:"POST",body:JSON.stringify({uuid:b.dataset.r,name:nn})}); loadUsers(); }catch(e){alert(e.message);} });
  tb.querySelectorAll("[data-x]").forEach(b=>b.onclick=async()=>{ if(!confirm("Remove player?"))return;
    try{ await api("/admin/user/"+encodeURIComponent(b.dataset.x),{method:"DELETE"}); loadUsers(); }catch(e){ alert(e.message); } });
}
$("#uReload").onclick=loadUsers;

armConfirm({btn:"#reset",box:"#resetBox",input:"#resetIn",go:"#resetGo",cancel:"#resetCancel",msg:"#dzMsg",word:"RESET",
  run:async()=>{ await api("/admin/reset",{method:"POST"}); const m=$("#dzMsg"); m.className="msg ok"; m.textContent="Scoreboard reset."; loadUsers(); }});
$("#rot").onclick=async()=>{ const nt=$("#newTok").value.trim(); if(nt.length<20){$("#dzMsg").className="msg bad";$("#dzMsg").textContent="Need >= 20 chars (use Generate).";return;}
  try{ await api("/admin/rotate-token",{method:"POST",body:JSON.stringify({new_token:nt})});
    TOKEN=nt; session.set("ctf_admin",nt); $("#dzMsg").className="msg ok"; $("#dzMsg").textContent="Rotated. New token active; the old one is dead."; $("#newTok").value=""; $("#newTok").type="password"; }
  catch(e){ $("#dzMsg").className="msg bad"; $("#dzMsg").textContent=e.message; } };

function download(name,text,type){
  const url=URL.createObjectURL(new Blob([text],{type})); const a=document.createElement("a");
  a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function csvCell(v){ v=String(v??""); if(/^[=+\-@\t\r]/.test(v)) v="'"+v; /* neutralize spreadsheet formulas (CSV injection) */ return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; }
function slug(s){ return (s||"ctf").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")||"ctf"; }
$("#expCsv").onclick=async()=>{
  try{
    const d=await api("/admin/export"); const b=d.leaderboard;
    const head=["rank","name","score","solves","last_solve"];
    const rows=[head.join(","),...b.map(r=>[r.rank,r.name,r.score,r.solves,r.last_solve].map(csvCell).join(","))];
    download(slug(d.event.name)+"-leaderboard.csv",rows.join("\n"),"text/csv");
    $("#expMsg").className="dim"; $("#expMsg").textContent=b.length+" players exported.";
  }catch(e){ $("#expMsg").className="bad"; $("#expMsg").textContent=e.message; }
};
$("#expJson").onclick=async()=>{
  try{
    const d=await api("/admin/export");
    download(slug(d.event.name)+"-export.json",JSON.stringify(d,null,2),"application/json");
    $("#expMsg").className="dim"; $("#expMsg").textContent=d.solves.length+" solves exported.";
  }catch(e){ $("#expMsg").className="bad"; $("#expMsg").textContent=e.message; }
};
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
if(TOKEN){ unlock(); }
