function $(id){ return document.getElementById(id); }
async function api(p,opt={}) {
  const r = await fetch('/api'+p, {credentials:'include', headers:{'Content-Type':'application/json'}, ...opt});
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}

document.addEventListener('DOMContentLoaded', () => {
  const openReg=$('btnOpenReg'), openLogin=$('btnOpenLogin'), btnLogout=$('btnLogout'), btnPause=$('btnPause'), who=$('who'), msg=$('msg');
  const btnPwd=$('btnPwd');
  const mReg=$('modalReg'), mLogin=$('modalLogin'), mPwd=$('modalPwd');
  const regUser=$('regUser'), regMail=$('regMail'), regPass=$('regPass'), regPass2=$('regPass2'), regGo=$('regGo'), regCancel=$('regCancel');
  const logUser=$('logUser'), logPass=$('logPass'), logGo=$('logGo'), logCancel=$('logCancel');
  const pwOld=$('pwOld'), pwNew1=$('pwNew1'), pwNew2=$('pwNew2'), pwSave=$('pwSave'), pwCancel=$('pwCancel');

  const cv=$('cv'), startOverlay=$('start'), startBtn=$('startBtn'), sc=$('sc'), hi=$('hi'), board=$('board');
  const ctx=cv.getContext('2d');

  const cell=30, gx=cv.width/cell, gy=cv.height/cell;
  const COLORS={grid:'#1f2a44', snake:'#22c55e', food:'#ef4444'};

  let authed=false, running=false, paused=false, loop=null;
  let sn, dir, food, score, alive;

  function isTypingTarget(e){
    const t = e.target;
    return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
  }

  const show=(el,on)=> el.style.display = on ? '' : 'none';
  const toggle=(el,on)=> el.classList.toggle('show', !!on);

  function updateOverlay(){
    if(!authed){ toggle(startOverlay,false); return; }
    if(!running){ startBtn.textContent='Start Game'; toggle(startOverlay,true); return; }
    if(paused){ startBtn.textContent='Resume'; toggle(startOverlay,true); return; }
    toggle(startOverlay,false);
  }

  function gate(){
    msg.style.display = authed ? 'none' : '';
    show(btnLogout, authed);
    show(btnPwd, authed);
    show(openLogin, !authed);
    show(openReg, !authed);
    show(btnPause, authed);
    btnPause.textContent = paused ? 'Resume' : 'Pause';
    updateOverlay();
  }

  openReg.onclick = ()=>{ regUser.value=''; regMail.value=''; regPass.value=''; regPass2.value=''; toggle(mReg,true); regUser.focus(); };
  regCancel.onclick = ()=> toggle(mReg,false);
  regGo.onclick = async ()=>{
    const u=regUser.value.trim(), e=regMail.value.trim(), p=regPass.value, p2=regPass2.value;
    if(u.length<3 || !e.includes('@') || p.length<6 || p!==p2){ alert('Bitte gültige Daten eingeben.'); return; }
    try{ await api('/register',{method:'POST',body:JSON.stringify({username:u,email:e,password:p})}); alert('Registriert – bitte einloggen.'); toggle(mReg,false); }
    catch(e){ alert('Registrierung fehlgeschlagen'); }
  };

  openLogin.onclick = ()=>{ logUser.value=''; logPass.value=''; toggle(mLogin,true); logUser.focus(); };
  logCancel.onclick = ()=> toggle(mLogin,false);
  logGo.onclick = async ()=>{
    const u=logUser.value.trim(), p=logPass.value;
    if(u.length<3 || p.length<6){ alert('Bitte gültige Zugangsdaten.'); return; }
    try{
      const me = await api('/login',{method:'POST',body:JSON.stringify({username:u,password:p})});
      authed=true; who.textContent='Eingeloggt als '+me.username; hi.textContent=me.highscore||0;
      toggle(mLogin,false); running=false; paused=false; gate(); cv.focus();
    }catch(e){ alert('Login fehlgeschlagen'); }
  };

  btnLogout.onclick = async ()=>{
    try{ await api('/logout',{method:'POST'}); }catch(_){}
    authed=false; who.textContent=''; running=false; paused=false; gate(); stop(); reset(); draw();
  };

  btnPwd.onclick = ()=>{ pwOld.value=''; pwNew1.value=''; pwNew2.value=''; toggle(mPwd,true); pwOld.focus(); };
  pwCancel.onclick = ()=> toggle(mPwd,false);
  pwSave.onclick = async ()=>{
    const o=pwOld.value, n1=pwNew1.value, n2=pwNew2.value;
    if(n1.length<6 || n1!==n2){ alert('Neues Passwort zu kurz oder stimmt nicht überein.'); return; }
    try{
      await api('/change_password',{method:'POST',body:JSON.stringify({old_password:o,new_password:n1})});
      toggle(mPwd,false);
      alert('Passwort aktualisiert. Bitte erneut einloggen.');
      authed=false; who.textContent=''; running=false; paused=false; gate(); stop(); reset(); draw();
    }catch(e){
      alert('Ändern fehlgeschlagen (altes Passwort korrekt?)');
    }
  };

  btnPause.onclick = ()=> {
    if(!authed) return;
    if(!running){ start(); return; }
    paused = !paused;
    btnPause.textContent = paused ? 'Resume' : 'Pause';
    updateOverlay();
    if(!paused) cv.focus();
  };

  startBtn.onclick = ()=> startOrToggle();

  const blockKeys = new Set(['ArrowUp','ArrowDown','ArrowLeft','ArrowRight','Space','KeyW','KeyA','KeyS','KeyD']);
  document.addEventListener('keydown', (e)=>{
    if(isTypingTarget(e)) return;
    if(blockKeys.has(e.code)) e.preventDefault();

    if(e.code === 'Space'){ startOrToggle(); return; }
    const keyMap = { ArrowUp:'u', KeyW:'u', ArrowDown:'d', KeyS:'d', ArrowLeft:'l', KeyA:'l', ArrowRight:'r', KeyD:'r' };
    const ndir = keyMap[e.code];
    if(!ndir || !authed || !running || paused) return;
    if((ndir==='u'&&dir!=='d')||(ndir==='d'&&dir!=='u')||(ndir==='l'&&dir!=='r')||(ndir==='r'&&dir!=='l')) dir=ndir;
  }, {passive:false});

  function startOrToggle(){
    if(!authed){ alert('Bitte erst einloggen.'); return; }
    if(!running){ if(!alive) reset(); start(); return; }
    paused = !paused;
    btnPause.textContent = paused ? 'Resume' : 'Pause';
    updateOverlay();
    if(!paused) cv.focus();
  }

  function pointerToCanvas(ev){
    const rect=cv.getBoundingClientRect();
    const cx = (ev.clientX ?? (ev.touches && ev.touches[0].clientX));
    const cy = (ev.clientY ?? (ev.touches && ev.touches[0].clientY));
    const scaleX = cv.width / rect.width;
    const scaleY = cv.height / rect.height;
    return { x:(cx-rect.left)*scaleX, y:(cy-rect.top)*scaleY };
  }
  function dirFromDelta(dx,dy){ const horiz=Math.abs(dx)>=Math.abs(dy); return horiz?(dx>0?'r':'l'):(dy>0?'d':'u'); }
  function setDir(ndir){ if((ndir==='u'&&dir!=='d')||(ndir==='d'&&dir!=='u')||(ndir==='l'&&dir!=='r')||(ndir==='r'&&dir!=='l')) dir=ndir; }

  let swipeStart=null, swipeDirLocked=false;

  cv.addEventListener('pointerdown', (ev)=>{
    if(!authed) return;
    ev.preventDefault();
    cv.focus();
    if(!running){ if(!alive) reset(); start(); }
    else if(paused){ paused=false; btnPause.textContent='Pause'; updateOverlay(); }
    const p = pointerToCanvas(ev);
    swipeStart = {x:p.x, y:p.y};
    swipeDirLocked = false;
  }, {passive:false});

  cv.addEventListener('pointermove', (ev)=>{
    if(!authed || !running || paused || !swipeStart) return;
    const p = pointerToCanvas(ev);
    const dx = p.x - swipeStart.x, dy = p.y - swipeStart.y;
    const dist = Math.hypot(dx,dy);
    if(dist > 24 && !swipeDirLocked){ setDir(dirFromDelta(dx,dy)); swipeDirLocked = true; }
  }, {passive:false});

  cv.addEventListener('pointerup', ()=>{ swipeStart=null; swipeDirLocked=false; });

  cv.addEventListener('click', (ev)=>{
    if(!authed || !running || paused) return;
    if(swipeDirLocked) return;
    const p = pointerToCanvas(ev);
    const hx=sn[0].x*cell+cell/2, hy=sn[0].y*cell+cell/2;
    const dx=p.x-hx, dy=p.y-hy;
    setDir(dirFromDelta(dx,dy));
  });

  function reset(){ sn=[{x:5,y:5}]; dir='r'; food=spawn(); score=0; alive=true; sc.textContent=0; }
  function spawn(){ return {x:Math.floor(Math.random()*gx), y:Math.floor(Math.random()*gy)} }
  function drawGrid(){ ctx.save(); ctx.strokeStyle=COLORS.grid; for(let x=0;x<=cv.width;x+=cell){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,cv.height);ctx.stroke();} for(let y=0;y<=cv.height;y+=cell){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(cv.width,y);ctx.stroke();} ctx.restore(); }
  function draw(){ ctx.clearRect(0,0,cv.width,cv.height); drawGrid(); ctx.fillStyle=COLORS.food; ctx.fillRect(food.x*cell, food.y*cell, cell, cell); ctx.fillStyle=COLORS.snake; sn.forEach(p=>ctx.fillRect(p.x*cell+4, p.y*cell+4, cell-8, cell-8)); }

  async function over(){
    alive=false; running=false; paused=false; updateOverlay();
    try{ const r=await api('/score',{method:'POST',body:JSON.stringify({score})}); hi.textContent=r.highscore; refreshBoard(); }catch(_){}
    setTimeout(()=>{ reset(); draw(); },200);
  }

  function tick(){
    if(!alive || !authed || !running || paused) return;
    const h={...sn[0]};
    if(dir==='u')h.y--; if(dir==='d')h.y++; if(dir==='l')h.x--; if(dir==='r')h.x++;
    h.x=(h.x+gx)%gx; h.y=(h.y+gy)%gy;
    if(sn.some((p,i)=>i&&p.x===h.x&&p.y===h.y)) return over();
    sn.unshift(h);
    if(h.x===food.x&&h.y===food.y){ score++; sc.textContent=score; food=spawn(); } else sn.pop();
    draw();
  }

  function start(){ running=true; paused=false; updateOverlay(); cv.focus(); }
  function stop(){ running=false; paused=false; }

  async function refreshBoard(){
    try{ const lb=await api('/leaderboard'); board.innerHTML=''; lb.forEach(x=>{ const li=document.createElement('li'); li.textContent=`${x.username} — ${x.highscore}`; board.appendChild(li); }); }catch(_){}
  }

  (async()=>{
    reset(); draw(); refreshBoard();
    try{ const me=await api('/me'); authed=true; who.textContent='Eingeloggt als '+me.username; hi.textContent=me.highscore||0; }catch(_){ }
    gate();
    if(!loop) loop=setInterval(tick,95);
  })();
});