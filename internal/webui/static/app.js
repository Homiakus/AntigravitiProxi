const $ = s => document.querySelector(s);
const csrf = () => document.cookie.split('; ').find(x=>x.startsWith('agp_csrf='))?.split('=')[1] || '';
const output = $('#output');
let state = null;
let assurance = null;
let tunnelTransient = '';

function pretty(v){ return typeof v === 'string' ? v : JSON.stringify(v,null,2); }
function setOutput(v){ output.textContent = pretty(v); output.scrollTop = 0; }
function setBusy(on){ document.querySelectorAll('button').forEach(b=>b.disabled=on); }
function setTunnelHint(text){
  tunnelTransient=String(text||'');
  const el=$('#tunnel-hint');
  if(el) el.textContent=tunnelTransient || state?.agent_tunnel_hint || '';
}
function esc(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function api(path, opts={}){
  const init = {...opts, headers:{...(opts.headers||{})}};
  if((init.method||'GET')!=='GET') init.headers['X-AGP-CSRF']=csrf();
  if(init.body && typeof init.body !== 'string'){
    init.headers['Content-Type']='application/json';
    init.body=JSON.stringify(init.body);
  }
  const r = await fetch(path,init);
  const text = await r.text();
  let data = text;
  try{ data = JSON.parse(text); }catch{}
  if(!r.ok) throw new Error(typeof data==='string' ? data.trim() : (data.error||JSON.stringify(data)));
  return data;
}

function interfaceIsUp(it){ return !!it?.flags?.includes('up'); }
function likelyVPNs(){ return (state?.interfaces||[]).filter(i=>i.likely_vpn && interfaceIsUp(i)); }
function selectedVPN(){ return String(state?.settings?.vpn_interface||''); }
function selectedVPNInfo(){ return (state?.interfaces||[]).find(i=>i.name===selectedVPN()) || null; }

function setSetupStep(id, mode, label){
  const el=$(id);
  if(!el) return;
  el.classList.remove('ready','auto','blocked','bad');
  if(mode) el.classList.add(mode);
  const b=el.querySelector('b');
  if(b) b.textContent=label;
}

function renderSetup(){
  if(!state) return;
  const linux=state.os==='linux';
  const tunnelActive=!!state.agent_tunnel_active;
  const health=String(state?.health?.state||'').toLowerCase();
  const vpn=selectedVPNInfo();
  const candidates=likelyVPNs();

  setSetupStep('#setup-singbox', state.sing_box_path?'ready':'auto', state.sing_box_path?'READY':'AUTO');

  if(vpn && interfaceIsUp(vpn)){
    setSetupStep('#setup-vpn','ready',vpn.name);
  }else if(!selectedVPN() && candidates.length){
    setSetupStep('#setup-vpn','auto','AUTO');
  }else{
    setSetupStep('#setup-vpn','blocked','НУЖЕН VPN');
  }

  if(linux){
    setSetupStep('#setup-privileges',tunnelActive?'ready':'auto',tunnelActive?'READY':'AUTO AUTH');
  }else if(state.os==='windows'){
    setSetupStep('#setup-privileges',tunnelActive?'ready':'auto',tunnelActive?'READY':'UAC');
  }else{
    setSetupStep('#setup-privileges','bad','UNSUPPORTED');
  }

  if(tunnelActive && health==='healthy') setSetupStep('#setup-runtime','ready','HEALTHY');
  else if(tunnelActive) setSetupStep('#setup-runtime','bad','DEGRADED');
  else setSetupStep('#setup-runtime','auto','ON START');

  const overall=$('#setup-overall');
  const note=$('#setup-note');
  if(overall){
    overall.classList.remove('ready','needs','active');
    if(tunnelActive && health==='healthy'){
      overall.textContent='TUNNEL READY';
      overall.classList.add('active');
    }else if((vpn && interfaceIsUp(vpn)) || (!selectedVPN() && candidates.length)){
      overall.textContent='ONE-CLICK READY';
      overall.classList.add('ready');
    }else{
      overall.textContent='НУЖЕН VPN';
      overall.classList.add('needs');
    }
  }
  if(note){
    if(tunnelActive && health==='healthy') note.textContent='Agent Tunnel активен. Ниже доступна независимая runtime attestation маршрута и egress.';
    else if(!selectedVPN() && candidates.length===1) note.textContent=`Найден VPN ${candidates[0].name}. При запуске Tunnel он будет выбран и сохранён автоматически.`;
    else if(!selectedVPN() && candidates.length>1) note.textContent='Найдено несколько VPN-интерфейсов. Выберите нужный в секции «Маршрут».';
    else if(vpn && interfaceIsUp(vpn) && linux) note.textContent='Маршрут готов. При первом запуске Linux может показать системный PolicyKit-диалог; пароль получает ОС, не приложение.';
    else if(vpn && interfaceIsUp(vpn)) note.textContent='Маршрут готов. Запуск Tunnel выполнит системную проверку привилегий автоматически.';
    else note.textContent='Выберите активный VPN-интерфейс в секции «Маршрут».';
  }

  const help=$('#vpn-help');
  if(help){
    if(vpn && interfaceIsUp(vpn)) help.textContent=`Выбран ${vpn.name}: ${vpn.addresses?.join(', ')||'без адреса'}`;
    else if(candidates.length===1) help.textContent=`Рекомендуемый VPN: ${candidates[0].name}. Он будет выбран автоматически при запуске.`;
    else if(candidates.length>1) help.textContent=`Доступные VPN-кандидаты: ${candidates.map(x=>x.name).join(', ')}`;
    else help.textContent='VPN-кандидат автоматически не найден — выберите интерфейс вручную.';
  }
}

async function refresh(){
  state=await api('/api/status');
  $('#proxy-state').textContent=state.proxy_running?'RUNNING':'OFF';
  $('#proxy-state').style.color=state.proxy_running?'var(--good)':'var(--muted)';

  const tunnel=$('#tunnel-state');
  if(!state.agent_tunnel_supported){
    tunnel.textContent='UNSUPPORTED';
    tunnel.style.color='var(--bad)';
  }else if(state.agent_tunnel_active){
    tunnel.textContent='ACTIVE';
    tunnel.style.color='var(--good)';
  }else{
    tunnel.textContent='OFF';
    tunnel.style.color='var(--muted)';
  }

  $('#ag-state').textContent=state.antigravity_path?'found':'not found';
  $('#platform-state').textContent=`${state.os}/${state.arch}`;
  $('#proxy-url').textContent=state.proxy_url;
  if($('#tunnel-hint') && !tunnelTransient) $('#tunnel-hint').textContent=state.agent_tunnel_hint||'';

  const sel=$('#vpn-interface');
  const current=state.settings.vpn_interface||'';
  const options=(state.interfaces||[]).map(i=>`<option value="${esc(i.name)}" ${i.name===current?'selected':''}>${i.likely_vpn?'★ ':''}${esc(i.name)}${i.flags?.includes('up')?'':' · DOWN'} — ${esc((i.addresses||[]).join(', '))}</option>`).join('');
  sel.innerHTML='<option value="">Auto detect VPN</option>'+options;
  $('#dns-provider').value=state.settings.dns_provider||'cloudflare';
  $('#proxy-port').value=state.settings.proxy_port||7890;
  $('#auto-open').checked=!!state.settings.auto_open;
  const fallback=$('#tunnel-domain-fallback');
  if(fallback) fallback.checked=!!state.settings.tunnel_domain_fallback;
  renderSetup();
}

function assuranceColor(v){
  if(v==='verified') return 'var(--good)';
  if(v==='degraded') return 'var(--bad)';
  if(v==='partial') return 'var(--warn)';
  return 'var(--muted)';
}
function isolationColor(v){
  if(v==='strict') return 'var(--good)';
  if(v==='isolation-relaxed') return 'var(--warn)';
  return 'var(--muted)';
}

function renderAssurance(v){
  assurance=v;
  const stateEl=$('#assurance-state');
  if(!stateEl) return;
  const level=String(v?.state||'idle').toLowerCase();
  stateEl.textContent=level.toUpperCase();
  stateEl.style.color=assuranceColor(level);

  const isolation=String(v?.isolation||'inactive').toLowerCase();
  const isolationEl=$('#assurance-isolation');
  if(isolationEl){
    isolationEl.textContent=isolation.toUpperCase();
    isolationEl.style.color=isolationColor(isolation);
  }
  const isolationDetail=$('#assurance-isolation-detail');
  if(isolationDetail) isolationDetail.textContent=v?.isolation_detail||'';

  const active=v?.pid_route?.active_candidate_pids?.length||0;
  const vpn=v?.pid_route?.vpn_direct_pids?.length||0;
  const ambiguous=v?.pid_route?.ambiguous_connections||0;
  const pidEl=$('#assurance-pids');
  pidEl.textContent=active?`${vpn}/${active}${ambiguous?` · amb ${ambiguous}`:''}`:'—';
  pidEl.style.color=active && vpn===active && !ambiguous?'var(--good)':(ambiguous?'var(--bad)':'var(--muted)');

  const egressEl=$('#assurance-egress');
  if(v?.egress?.available){
    const count=v.egress.vpn_observed_ips?.length||0;
    egressEl.textContent=`PROVEN${count>1?` · ${count} IPs`:''}`;
    egressEl.style.color='var(--good)';
  }else{
    egressEl.textContent='UNAVAILABLE';
    egressEl.style.color=level==='degraded'?'var(--bad)':'var(--muted)';
  }

  const ageEl=$('#assurance-age');
  if(v?.egress?.observed_at){
    const observed=new Date(v.egress.observed_at);
    const age=Math.max(0,Math.round((Date.now()-observed.getTime())/1000));
    const until=v.egress_fresh_until?new Date(v.egress_fresh_until):null;
    const left=until?Math.max(0,Math.ceil((until.getTime()-Date.now())/1000)):0;
    ageEl.textContent=`${v.egress_cached?'cached':'fresh'} · ${age}s${until?` · TTL ${left}s`:''}`;
  }else{
    ageEl.textContent='—';
  }
  ageEl.style.color=v?.egress_cached?'var(--warn)':'var(--muted)';
  $('#assurance-detail').textContent=v?.detail||'Нет evidence.';
}

async function refreshAssurance(){
  try{
    renderAssurance(await api('/api/attestation'));
  }catch(e){
    const stateEl=$('#assurance-state');
    if(stateEl){
      stateEl.textContent='ERROR';
      stateEl.style.color='var(--bad)';
      $('#assurance-detail').textContent=e.message;
    }
  }
}

async function saveConfigFromUI(){
  return api('/api/config',{method:'POST',body:{
    vpn_interface:$('#vpn-interface').value,
    dns_provider:$('#dns-provider').value,
    proxy_port:Number($('#proxy-port').value),
    auto_open:$('#auto-open').checked,
    tunnel_domain_fallback:!!$('#tunnel-domain-fallback')?.checked
  }});
}

async function prepareTunnelRoute(){
  let chosen=$('#vpn-interface').value;
  if(!chosen){
    const candidates=likelyVPNs();
    if(candidates.length===1){
      chosen=candidates[0].name;
      $('#vpn-interface').value=chosen;
      setTunnelHint(`Автоматически выбран VPN ${chosen}. Сохраняю маршрут…`);
    }else if(candidates.length>1){
      throw new Error(`Найдено несколько VPN-интерфейсов (${candidates.map(x=>x.name).join(', ')}). Выберите нужный в секции «Маршрут».`);
    }else{
      throw new Error('Активный VPN-интерфейс не найден. Подключите VPN и выберите его в секции «Маршрут».');
    }
  }

  if(chosen!==selectedVPN()){
    if(state?.proxy_running){
      setTunnelHint('Маршрут изменён: безопасно останавливаю текущий managed data plane перед сохранением…');
      await api('/api/actions/stop',{method:'POST'});
      await refresh();
    }
    setTunnelHint(`Сохраняю VPN ${chosen} и параметры Tunnel…`);
    await saveConfigFromUI();
    await refresh();
  }
}

function friendlyTunnelError(message){
  const m=String(message||'');
  const l=m.toLowerCase();
  if(l.includes('policykit') || l.includes('pkexec')) return `${m}\n\nПодсказка: подтвердите системный PolicyKit-диалог. AntigravitiProxi не читает пароль.`;
  if(l.includes('cap_net_') || l.includes('cap_sys_ptrace') || l.includes('cap_dac_read_search')) return `${m}\n\nПрограмма попыталась выдать capabilities автоматически. Если системный диалог был отклонён — повторите запуск и подтвердите его.`;
  if(l.includes('/dev/net/tun') || l.includes('modprobe')) return `${m}\n\nПроверьте, что ядро поддерживает TUN. На обычном Ubuntu программа сама вызывает modprobe tun через PolicyKit.`;
  if(l.includes('vpn.not_') || l.includes('vpn interface') || l.includes('selected vpn')) return `${m}\n\nПодключите VPN и выберите активный интерфейс в секции «Маршрут».`;
  if(l.includes('routing.ownership_collision') || l.includes('preexisting')) return `${m}\n\nОбнаружено чужое или оставшееся сетевое состояние. Оно не удаляется автоматически без доказанного ownership.`;
  return m;
}

async function action(name){
  const tunnelAction=name==='tunnel/start'||name==='tunnel/launch'||name==='tunnel/stop';
  try{
    setBusy(true);
    let res;

    if(name==='tunnel/start'||name==='tunnel/launch'){
      setTunnelHint('Agent Tunnel: готовлю маршрут и проверяю prerequisites…');
      setOutput('Agent Tunnel: подготовка…');
      await prepareTunnelRoute();
      const authHint=state?.os==='linux'?' При необходимости подтвердите системный PolicyKit-диалог.':'';
      setTunnelHint('Проверяю TUN, capability tooling и минимальные права managed sing-box…'+authHint);
    }else if(name==='tunnel/stop'){
      setTunnelHint('Останавливаю Agent Tunnel и освобождаю managed network state…');
      setOutput('Останавливаю Agent Tunnel…');
    }

    if(name==='refresh'){
      await Promise.all([refresh(),refreshAssurance()]);
      return;
    }
    if(name==='clear-output'){
      setOutput('Готово.');
      return;
    }
    if(name==='attestation'){
      res=await api('/api/attestation');
      renderAssurance(res);
    }else if(name==='save-config'){
      res=await saveConfigFromUI();
    }else if(name==='diagnostics'){
      res=await api('/api/diagnostics');
    }else if(name==='agent-doctor'){
      res=await api('/api/agent-doctor');
    }else if(name==='logs'){
      res=await api('/api/logs');
    }else{
      const path=name
        .replace('hosts-enable','hosts/enable')
        .replace('hosts-disable','hosts/disable');
      res=await api('/api/actions/'+path,{method:'POST'});
    }

    if(tunnelAction){
      setTunnelHint(name==='tunnel/stop'?'Agent Tunnel остановлен.':'Agent Tunnel поднят. Собираю runtime evidence…');
    }
    setOutput(res);
    await Promise.all([refresh(),refreshAssurance()]);
    if(tunnelAction) setTimeout(()=>setTunnelHint(''),3500);
  }catch(e){
    const message=friendlyTunnelError(e?.message||e||'unknown error');
    setOutput('ERROR\n'+message);
    if(tunnelAction){
      setTunnelHint('Agent Tunnel НЕ запущен: '+message.split('\n')[0]);
      const panel=$('#agent-tunnel-panel');
      if(panel) panel.scrollIntoView({behavior:'smooth',block:'center'});
      renderSetup();
    }
  }finally{
    setBusy(false);
  }
}

document.addEventListener('click',e=>{
  const b=e.target.closest('[data-action]');
  if(b) action(b.dataset.action);
});

document.addEventListener('change',e=>{
  if(e.target?.id==='vpn-interface'){
    const v=e.target.value;
    const info=(state?.interfaces||[]).find(i=>i.name===v);
    const help=$('#vpn-help');
    if(help) help.textContent=info?`${info.flags?.includes('up')?'Активен':'DOWN'} · ${(info.addresses||[]).join(', ')}`:'Автоматический выбор будет выполнен при запуске Tunnel.';
  }
});

function connectEvents(){
  const es=new EventSource('/api/events');
  es.onopen=()=>{
    $('#live-dot').classList.add('on');
    $('#live-text').textContent='live';
  };
  es.onerror=()=>{
    $('#live-dot').classList.remove('on');
    $('#live-text').textContent='reconnect…';
  };
  es.onmessage=e=>{
    try{
      const v=JSON.parse(e.data);
      const row=document.createElement('div');
      row.className='event '+v.level;
      const t=new Date(v.time);
      row.innerHTML=`<span class="time">${t.toLocaleTimeString()}</span><span class="level">${esc(v.level)}</span><span>${esc(v.message)}</span>`;
      $('#events').prepend(row);
      while($('#events').children.length>250) $('#events').lastChild.remove();
    }catch{}
  };
}

if('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(()=>{});
Promise.all([refresh(),refreshAssurance()]).catch(e=>setOutput(e.message));
connectEvents();
setInterval(()=>{
  refresh().catch(()=>{});
  refreshAssurance().catch(()=>{});
},5000);
