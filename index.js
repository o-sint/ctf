/* ============ CONFIG ============ */
const API = "/api"; // same host as GitHub Pages via Worker route. If using a separate api subdomain, set full URL e.g. "https://ctf-api.example.com/api"
/* ================================ */

const $ = (s,r=document)=>r.querySelector(s);
const uuidKey="ctf_uuid", nameKey="ctf_name";
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
const store=makeStore("localStorage");
function newUuid(){
  if(crypto.randomUUID) return crypto.randomUUID();
  const b=crypto.getRandomValues(new Uint8Array(16)); b[6]=(b[6]&0x0f)|0x40; b[8]=(b[8]&0x3f)|0x80;
  const h=[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
let UUID = store.get(uuidKey);
if(!UUID){ UUID = newUuid(); store.set(uuidKey,UUID); }
let NAME = store.get(nameKey) || "";
let STATE=null, CH=[], ICONS={};
let OFFSET=0, LAST_PHASE="", BOARD_SIG="", CH_SIG="", holdTimer=0, lastFocus=null, lastFocusId="";
const serverNow=()=>Date.now()+OFFSET; // server-time clock (offset measured from /state)

async function api(path,opts={}){
  let r;
  try{ r = await fetch(API+path,{...opts,headers:{"Content-Type":"application/json",...(opts.headers||{})}}); }
  catch(e){ const er=new Error("network error"); er.status=0; er.data={}; throw er; }
  const j = await r.json().catch(()=>({error:"bad response"}));
  if(!r.ok){ const er=new Error(j.error||("HTTP "+r.status)); er.status=r.status; er.data=j; throw er; } // callers can read er.data (e.g. cooldown info)
  return j;
}
const fmt=(ms)=>{ if(ms<0)ms=0; const s=Math.floor(ms/1000); const h=Math.floor(s/3600),m=Math.floor(s%3600/60),ss=s%60;
  return [h,m,ss].map(x=>String(x).padStart(2,"0")).join(":"); };

function renderIdbar(){
  const bar=$("#idbar");
  if(NAME){
    bar.innerHTML=`<span class="who">playing as: <b>${esc(NAME)}</b></span>
      <button id="editName" class="ghost">Change name</button>
      <button id="delName" class="danger">Remove me</button>`;
    $("#editName").onclick=()=>promptName(NAME);
    $("#delName").onclick=removeMe;
  }else{
    bar.innerHTML=`<input type="text" id="nameIn" placeholder="pick a username" maxlength="24" />
      <button id="joinBtn" class="primary">Join</button>
      <span class="sub" id="joinMsg"></span>`;
    $("#joinBtn").onclick=()=>startJoin($("#nameIn").value);
    $("#nameIn").onkeydown=(e)=>{if(e.key==="Enter")startJoin($("#nameIn").value);};
  }
}
function startJoin(v){
  const name=(v||"").trim(); if(!name) return;
  if(STATE && STATE.code_required) openCodeModal(name);
  else promptName(name);
}
function openCodeModal(name){
  const card=$("#modalCard");
  card.innerHTML=`
    <span class="x" id="close" role="button" tabindex="0" aria-label="Close">✕</span>
    <h2>Access code</h2>
    <div class="code-sub">Enter the code to join as <b>${esc(name)}</b>.</div>
    <div class="row code-sub"><input type="text" id="codeModalIn" placeholder="access code" autocomplete="off"/>
      <button class="primary" id="codeModalBtn">Join</button></div>
    <div class="msg" id="codeModalMsg"></div>`;
  $("#close").onclick=closeModal;
  const submit=()=>promptName(name,$("#codeModalIn").value,"#codeModalMsg");
  $("#codeModalBtn").onclick=submit;
  $("#codeModalIn").onkeydown=(e)=>{if(e.key==="Enter")submit();};
  openModal();
  $("#codeModalIn").focus();
}
async function promptName(v,code,errTarget){
  const name=(v||"").trim(); if(!name) return;
  try{
    const j=await api("/register",{method:"POST",body:JSON.stringify({uuid:UUID,name,code:code||""})});
    NAME=j.name; store.set(nameKey,NAME); renderIdbar(); loadBoard().catch(()=>{});
    if(errTarget) closeModal();
  }catch(e){
    const m=errTarget?$(errTarget):$("#joinMsg");
    if(m){m.textContent=e.message;m.className=(errTarget?"msg":"sub")+" bad";} else alert(e.message);
  }
}
async function removeMe(){
  if(!confirm("Remove your username and all your solves?")) return;
  try{ await api("/unregister",{method:"POST",body:JSON.stringify({uuid:UUID})}); }catch(e){}
  forgetIdentity(); CH_SIG=""; loadChallenges().catch(()=>{});
}
function forgetIdentity(note){
  NAME=""; store.del(nameKey); BOARD_SIG=""; renderIdbar();
  if(note){ const m=$("#joinMsg"); if(m){ m.textContent=note; m.className="sub bad"; } }
  loadBoard().catch(()=>{});
}
// Reconcile with the server so an admin rename/removal or a scoreboard reset can't leave a player stuck on a dead identity.
// Only an explicit {registered:false} counts — a bare 404 (e.g. an older Worker without /me) never wipes anyone.
async function loadMe(){
  if(!NAME) return;
  try{
    const j=await api("/me",{headers:{"X-Player-Id":UUID}});
    if(j.name && j.name!==NAME){ NAME=j.name; store.set(nameKey,NAME); BOARD_SIG=""; renderIdbar(); loadBoard().catch(()=>{}); }
  }catch(e){ if(e.data && e.data.registered===false) forgetIdentity("Your username was removed. Pick one again."); }
}

function phaseNow(){
  if(!STATE||!STATE.start||!STATE.end) return "unset";
  const t=serverNow();
  return t<STATE.start?"pre":t>STATE.end?"post":"live";
}
function paintClock(){
  if(!STATE) return;
  const p=phaseNow(), ph=$("#phase"), c=$("#clock"), t=serverNow();
  ph.className="pill "+p;
  if(p==="pre"){ph.textContent="starts soon"; c.textContent=fmt(STATE.start-t);}
  else if(p==="live"){ph.textContent="LIVE"; c.textContent=fmt(STATE.end-t);}
  else if(p==="post"){ph.textContent="ended"; c.textContent="00:00:00";}
  else{ph.textContent="not scheduled"; c.textContent="--:--:--";}
}
async function loadState(){
  STATE=await api("/state");
  OFFSET=STATE.now-Date.now();
  $("#evname").textContent=STATE.name||"(unnamed event)";
  LAST_PHASE=STATE.phase;
  paintClock();
}
// The 1 Hz clock runs locally (no network). A phase flip (start/end) triggers exactly one refresh.
function tick(){
  if(document.hidden||!STATE) return;
  const p=phaseNow();
  paintClock();
  if(p!==LAST_PHASE){ LAST_PHASE=p; STATE.phase=p; refresh(); }
}
async function loadBoard(){
  const j=await api("/leaderboard");
  loadScoreboard(j).catch(()=>{}); // reuse this response for the chart instead of fetching /leaderboard a second time
  $("#lbTotal").textContent=j.board.length?" ("+j.board.length+")":"";
  const sig=NAME+"|"+JSON.stringify(j.board);
  if(sig===BOARD_SIG) return; BOARD_SIG=sig; // nothing changed: skip the table rebuild
  const tb1=$("#board1 tbody"), tb2=$("#board2 tbody");
  tb1.innerHTML=""; tb2.innerHTML="";
  if(!j.board.length){
    tb1.innerHTML=`<tr><td colspan="3" class="sub" style="padding:14px">No players yet. Be the first — pick a username above.</td></tr>`;
    $("#board2").style.display="none";
    return;
  }
  $("#board2").style.display="";
  const half=Math.ceil(j.board.length/2);
  j.board.forEach((row,i)=>{
    const tr=document.createElement("tr");
    if(row.name===NAME) tr.className="me";
    const rc = i<3?("r"+(i+1)):"";
    tr.innerHTML=`<td class="rank ${rc}">${i+1}</td><td>${esc(row.name)}</td><td class="pts">${row.score}</td>`;
    (i<half?tb1:tb2).appendChild(tr);
  });
  $("#board2").style.display=tb2.children.length?"":"none";
}
const SB_COLORS=["#37e0a0","#4aa3ff","#ffcf5c","#ff6b6b","#c792ea","#7fd1ff","#f78c6c","#82aaff","#c3e88d","#ff9cac"];
function fmtTick(ms){ const d=new Date(ms); const p=n=>String(n).padStart(2,"0");
  return `${p(d.getMonth()+1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; }
function niceMax(n){ if(n<=0)return 10; const mag=Math.pow(10,Math.floor(Math.log10(n)));
  const norm=n/mag; const step=norm<=1?1:norm<=2?2:norm<=5?5:10; return step*mag; }

async function loadScoreboard(board){
  try{
    const tl=await api("/timeline");
    const solves=(tl.solves||[]).slice().sort((a,b)=>a.ts_ms-b.ts_ms);
    const byName={};
    solves.forEach(s=>{(byName[s.name]=byName[s.name]||[]).push(s);});
    const top=board.board.filter(b=>b.solves>0).slice(0,10);
    $("#sbMsg").textContent = board.board.length ? board.board.length+" player"+(board.board.length===1?"":"s") : "";
    drawWorm(top, byName, tl.event||{}, solves);
  }catch(e){ /* leave prior chart in place on transient error */ }
}
function drawWorm(top, byName, event, allSolves){
  const svg=$("#sbChart");
  const W=900,H=340,padL=46,padR=100,padT=14,padB=34;
  svg.innerHTML="";
  $("#sbLegend").innerHTML="";
  if(!top.length || !allSolves.length){
    svg.innerHTML=`<text x="${W/2}" y="${H/2}" fill="#8090b3" font-family="monospace" font-size="13" text-anchor="middle">no scored solves yet</text>`;
    return;
  }
  const tsAll=allSolves.map(s=>s.ts_ms);
  const xMin=event.start||Math.min(...tsAll);
  const latest=Math.max(Date.now(),...tsAll);
  const xEnd=Math.max(xMin+1, event.end&&event.end>xMin?Math.min(event.end,latest):latest);
  const maxScore=niceMax(Math.max(...top.map(b=>b.score),1));
  const x=(ms)=>padL+((ms-xMin)/(xEnd-xMin||1))*(W-padL-padR);
  const xc=(ms)=>x(Math.max(xMin,Math.min(xEnd,ms))); // clamp to the visible window so solves from an older imported event don't push the line off-chart
  const y=(v)=>H-padB-(v/maxScore)*(H-padT-padB);

  let svgEls="";
  for(let i=0;i<=4;i++){
    const v=Math.round(maxScore*i/4);
    const yy=y(v);
    svgEls+=`<line x1="${padL}" y1="${yy}" x2="${W-padR}" y2="${yy}" stroke="#243049" stroke-width="1"/>`;
    svgEls+=`<text x="${padL-8}" y="${yy+4}" fill="#8090b3" font-family="monospace" font-size="11" text-anchor="end">${v}</text>`;
  }
  [xMin,(xMin+xEnd)/2,xEnd].forEach(t=>{
    svgEls+=`<text x="${x(t)}" y="${H-padB+18}" fill="#8090b3" font-family="monospace" font-size="11" text-anchor="middle">${fmtTick(t)}</text>`;
  });

  const labels=[];
  top.forEach((b,i)=>{
    const color=SB_COLORS[i%SB_COLORS.length];
    const pts=byName[b.name]||[];
    let cum=0; const path=[`M ${x(xMin)} ${y(0)}`];
    pts.forEach(s=>{
      path.push(`L ${xc(s.ts_ms)} ${y(cum)}`);
      cum+=s.points;
      path.push(`L ${xc(s.ts_ms)} ${y(cum)}`);
    });
    path.push(`L ${x(xEnd)} ${y(cum)}`);
    svgEls+=`<path d="${path.join(" ")}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>`;
    pts.forEach(s=>{
      let c2=0; for(const p of pts){ c2+=p.points; if(p===s)break; }
      svgEls+=`<circle cx="${xc(s.ts_ms)}" cy="${y(c2)}" r="2.5" fill="${color}"/>`;
    });
    const label=b.name.length>13?b.name.slice(0,12)+"…":b.name;
    labels.push({y:y(cum),color,label});
  });
  labels.sort((a,b)=>a.y-b.y);
  for(let i=1;i<labels.length;i++){
    if(labels[i].y-labels[i-1].y<13) labels[i].y=labels[i-1].y+13;
  }
  labels.forEach(l=>{ svgEls+=`<text x="${x(xEnd)+4}" y="${l.y+3}" fill="${l.color}" font-family="monospace" font-size="11">${esc(l.label)}</text>`; });
  svg.innerHTML=svgEls;

  $("#sbLegend").innerHTML=top.map((b,i)=>`<span style="display:inline-flex;align-items:center;gap:5px;margin-right:12px">
    <span style="width:10px;height:10px;border-radius:2px;background:${SB_COLORS[i%SB_COLORS.length]};display:inline-block"></span>${esc(b.name)} <span class="sub">(${b.score})</span></span>`).join("");
}

async function loadChallenges(){
  const note=$("#chNote"), cats=$("#cats");
  const j=await api("/challenges?uuid="+encodeURIComponent(UUID));
  CH=j.challenges; ICONS=j.icons||{}; const icons=ICONS;
  const sig=(STATE?STATE.phase:"")+"|"+JSON.stringify(j);
  if(sig===CH_SIG) return; CH_SIG=sig; // nothing changed: skip the DOM rebuild
  if(j.phase==="pre"||j.phase==="unset"){ note.textContent = j.phase==="pre"?"Challenges unlock when the event starts.":"No event scheduled yet."; cats.innerHTML=""; $("#chTotal").textContent=""; return; }
  note.textContent="";
  $("#chTotal").textContent=" ("+CH.length+")";
  const groups={};
  CH.forEach(c=>{(groups[c.category]=groups[c.category]||[]).push(c);});
  cats.innerHTML="";
  Object.keys(groups).sort().forEach(cat=>{
    const div=document.createElement("div"); div.className="cat";
    const icon=icons[cat];
    div.innerHTML=`<h3>${icon?`<img src="${esc(icon)}" width="16" height="16" style="vertical-align:-3px;margin-right:6px"/>`:""}${esc(cat)}</h3><div class="tiles"></div>`;
    const tiles=$(".tiles",div);
    groups[cat].forEach(c=>{
      const t=document.createElement("div"); t.className="tile"+(c.solved?" solved":"");
      const noSolves=STATE&&STATE.phase==="live"&&c.solves===0;
      t.innerHTML=`<span class="t">${esc(c.title)}</span><span class="v"${noSolves?' style="color:var(--warn)"':""}>${c.value}</span>`;
      t.onclick=()=>openChallenge(c.id);
      t.setAttribute("role","button"); t.tabIndex=0;
      t.onkeydown=(e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); openChallenge(c.id); } };
      tiles.appendChild(t);
    });
    cats.appendChild(div);
  });
}
function openChallenge(id){
  const c=CH.find(x=>x.id===id); if(!c) return;
  const card=$("#modalCard");
  const hintCtl = c.has_hint ? (c.hint
      ? `<div class="hintbox"><div class="sub">Hint (unlocked)</div><div class="h">${esc(c.hint)}</div></div>`
      : `<div class="hintbox"><button id="hintBtn" class="ghost">Unlock hint (−${c.hint_cost} pts)</button></div>`) : "";
  const isPost = STATE && STATE.phase==="post";
  const noSolves = STATE && STATE.phase==="live" && c.solves===0;
  const ansCtl = `<div class="hintbox">
    <button id="showAns" class="ghost"${isPost?"":' disabled title="wait for the CTF to end"'}>Show answer</button>
    <div class="h" id="ansText" style="display:none"></div>
  </div>`;
  const catIcon=ICONS[c.category];
  card.innerHTML=`
    <span class="x" id="close" role="button" tabindex="0" aria-label="Close">✕</span>
    <div class="cat-lbl">${catIcon?`<img src="${esc(catIcon)}" width="25" height="25" style="vertical-align:-5px;margin-right:6px"/>`:""}${esc(c.category)}</div>
    <h3>${esc(c.title)}</h3>
    <div class="val"${noSolves?' style="color:var(--warn)"':""}>${c.value} pts · ${c.solves} solve(s)</div>
    <div class="prompt">${linkify(c.prompt)}</div>
    ${c.solved
      ? `<div class="msg ok">Solved ✓</div>`
      : `<div class="row"><input type="text" id="ans" placeholder="answer" autocomplete="off"/><button class="primary" id="sub">Submit</button></div>
         <div class="sub" id="att">${c.attempts_left} attempt(s) left</div>
         <div class="msg" id="m"></div>`}
    ${hintCtl}
    ${ansCtl}`;
  $("#close").onclick=closeModal;
  if(!c.solved){
    const inp=$("#ans");
    $("#sub").onclick=()=>doSubmit(c.id);
    inp.onkeydown=(e)=>{if(e.key==="Enter")doSubmit(c.id);};
    inp.focus();
    tickHoldoff(c);
  }
  if(c.has_hint && !c.hint){ $("#hintBtn").onclick=()=>doHint(c.id); }
  if(isPost){
    $("#showAns").onclick=async()=>{
      const btn=$("#showAns"), out=$("#ansText");
      btn.disabled=true; btn.textContent="Loading…";
      try{
        const sol=await solutionFor(c.id);
        out.innerHTML=linkify(sol||"(no solution recorded)");
        out.style.display="block";
        btn.style.display="none";
      }catch(e){ btn.disabled=false; btn.textContent="Show answer"; alert(e.message); }
    };
  }
  openModal();
  const a=$("#ans"); if(a) a.focus();
}
function tickHoldoff(c){ // one interval, cleared on close / next call (no stacked timers)
  clearInterval(holdTimer);
  const btn=$("#sub"); if(!btn) return;
  const until=c.holdoff_until||0;
  const upd=()=>{ const left=until-serverNow();
    if(left>0){ btn.disabled=true; btn.textContent="wait "+Math.ceil(left/1000)+"s"; }
    else{ btn.disabled=false; btn.textContent="Submit"; clearInterval(holdTimer); } };
  upd();
  holdTimer=setInterval(upd,250);
}
async function doSubmit(id){
  const m=$("#m"), att=$("#att"), inp=$("#ans");
  const answer=inp.value; if(!answer.trim()) return;
  try{
    const j=await api("/submit",{method:"POST",body:JSON.stringify({uuid:UUID,challenge_id:id,answer})});
    if(j.correct){
      m.className="msg ok"; m.textContent = j.scored?`Correct! +${j.points}`:"Correct (practice — event over, 0 pts)";
      await loadChallenges(); await loadBoard();
      const c=CH.find(x=>x.id===id); if(c){c.solved=true;}
      setTimeout(()=>{closeModal();},900);
    }else{
      m.className="msg bad";
      if(j.holdoff_until && (!j.attempts_left && j.attempts_left!==0)){ m.textContent="Too fast — wait for the timer."; }
      else{ m.textContent="Nope."; }
      if(j.attempts_left!=null){ att.textContent=j.attempts_left+" attempt(s) left"; }
      const c=CH.find(x=>x.id===id); if(c){c.holdoff_until=j.holdoff_until; tickHoldoff(c);}
    }
  }catch(e){
    const d=e.data||{}; m.className="msg bad";
    if(e.status===403 && /register/i.test(e.message)){
      if(!NAME) showNeedNamePopup(); else { forgetIdentity("Your username was removed. Pick one again."); closeModal(); }
      return;
    }
    if(d.attempts_left!==undefined && att) att.textContent=d.attempts_left+" attempt(s) left";
    if(d.holdoff_until){ m.textContent="Too fast — wait for the timer."; const c=CH.find(x=>x.id===id); if(c){ c.holdoff_until=d.holdoff_until; tickHoldoff(c); } }
    else m.textContent=e.message;
  }
}
async function doHint(id){
  try{
    const j=await api("/hint",{method:"POST",body:JSON.stringify({uuid:UUID,challenge_id:id})});
    const c=CH.find(x=>x.id===id); if(c){c.hint=j.hint;}
    openChallenge(id); await loadBoard();
  }catch(e){
    if(e.status===403 && /register/i.test(e.message)){
      if(!NAME) showNeedNamePopup(); else { forgetIdentity("Your username was removed. Pick one again."); closeModal(); }
      return;
    }
    alert(e.message);
  }
}
function openModal(){
  const m=$("#modal");
  // remember what opened the dialog — only the first time (unlocking a hint re-renders the already-open dialog)
  if(!m.classList.contains("open")){ lastFocus=document.activeElement; lastFocusId=(lastFocus&&lastFocus.dataset&&lastFocus.dataset.id)||""; }
  m.classList.add("open");
}
function showNeedNamePopup(){
  const card=$("#modalCard");
  card.innerHTML=`
    <span class="x" id="close" role="button" tabindex="0" aria-label="Close">✕</span>
    <h2>Pick a username first</h2>
    <div class="code-sub">You need to register a username before you can play.</div>
    <div class="row" style="margin-top:14px"><button class="primary" id="needNameOk">OK</button></div>`;
  $("#close").onclick=closeModal;
  $("#needNameOk").onclick=closeModal;
  openModal();
}
function closeModal(){
  clearInterval(holdTimer);
  $("#modal").classList.remove("open");
  let el=lastFocus;
  if((!el||!el.isConnected) && lastFocusId) el=document.querySelector('.tile[data-id="'+CSS.escape(lastFocusId)+'"]'); // the grid may have been rebuilt meanwhile
  if(el && el.focus) try{ el.focus(); }catch(e){}
}
$("#modal").onclick=(e)=>{ if(e.target.id==="modal") closeModal(); };
document.addEventListener("keydown",(e)=>{ if(e.key==="Escape") closeModal(); });
$("#modal").addEventListener("keydown",(e)=>{ if((e.key==="Enter"||e.key===" ") && e.target.id==="close"){ e.preventDefault(); closeModal(); } });

let SOLUTIONS_CACHE=null;
async function solutionFor(id){
  if(!SOLUTIONS_CACHE){
    const j=await api("/solutions");
    SOLUTIONS_CACHE={}; j.solutions.forEach(s=>{SOLUTIONS_CACHE[s.id]=s.solution;});
  }
  return SOLUTIONS_CACHE[id];
}

function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function linkify(s){ // escape first, then link; stop at escaped quote/angle entities so they can never end up inside an href
  return esc(s).replace(/(https?:\/\/(?:(?!&(?:quot|#39|lt|gt);)\S)+)/g,'<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>'); }

async function refresh(){ try{ await loadState(); await Promise.all([loadBoard(),loadChallenges(),loadMe()]); }catch(e){ console.error(e); } }
renderIdbar();
refresh();
// Polling is deliberately light (free-tier friendly): the clock ticks locally, /state is re-read once a minute,
// and nothing polls while the tab is hidden.
const quiet=(fn)=>()=>{ if(!document.hidden) Promise.resolve().then(fn).catch(()=>{}); };
setInterval(tick,1000);
setInterval(quiet(()=>Promise.all([loadState(),loadMe()])),60000);
setInterval(quiet(loadBoard),15000);      // also redraws the chart (/timeline is edge-cached)
setInterval(quiet(loadChallenges),30000);
document.addEventListener("visibilitychange",()=>{ if(!document.hidden) refresh(); });
