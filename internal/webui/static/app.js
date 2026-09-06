const $ = s => document.querySelector(s);
const csrf = () => document.cookie.split('; ').find(x=>x.startsWith('agp_csrf='))?.split('=')[1] || '';
const output = $('#output');
let state = null;
let assurance = null;
let diagnostics = null;
let refreshInFlight = false;
let assuranceInFlight = false;
let toastTimer = null;

function showToast(msg, tone='info'){
  const t = $('#toast');
  if(!t) return;
  t.textContent = msg;
  t.className = 'toast show ' + tone;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>{ t.className = 'toast'; }, 2600);
}

function pretty(v){ return typeof v === 'string' ? v : JSON.stringify(v,null,2); }
function setOutput(v){ output.textContent = pretty(v); output.scrollTop = 0; }
function setBusy(on){ document.querySelectorAll('button').forEach(b=>b.disabled=on); }
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

function setMetric(id, text, tone=''){
  const el=$(id);
  if(!el) return;
  el.textContent=text;
  el.dataset.state=tone;
}

function renderPolicy(){
  if(!state) return;
  const banner=$('#policy-banner');
  const title=$('#policy-title');
  const detail=$('#policy-detail');
  const warning=$('#fallback-warning');
  const fallback=$('#tunnel-domain-fallback') ? !!$('#tunnel-domain-fallback').checked : !!state.settings?.tunnel_domain_fallback;
  if(warning) warning.hidden=!fallback;
  if(!banner||!title||!detail) return;
  banner.classList.remove('strict','relaxed','bad');
  if(!state.agent_tunnel_supported){
    banner.classList.add('bad');
    title.textContent='Agent Tunnel недоступен';
    detail.textContent='Эта платформа не поддерживает TUN режим.';
  }else if(state.tunnel_enforcement==='kernel-hard'){
    banner.classList.add('strict');
    title.textContent='Kernel hard isolation active';
    detail.textContent='Antigravity работает в отдельном namespace и cgroup; kernel kill-switch разрешает выход только через выбранный VPN.';
  }else if(fallback){
    banner.classList.add('relaxed');
    title.textContent='Изоляция ослаблена';
    detail.textContent='Нераспознанные процессы с Google endpoints тоже могут пойти через VPN. Для строгой изоляции выключите fallback ниже.';
  }else{
    banner.classList.add('strict');
    title.textContent='Строгая изоляция включена';
    detail.textContent='Через VPN пойдут только распознанные процессы и пути Antigravity. Остальные приложения сохраняют system-direct.';
  }
}

function renderDiagnostics(v){
  diagnostics=v;
  const panel=$('#diagnostics-panel');
  const summary=$('#diagnostics-summary');
  if(!summary) return;
  panel?.classList.remove('loading');
  const dns=Array.isArray(v?.dns)?v.dns:[];
  const suspicious=dns.filter(x=>x.suspicious).length;
  const vpn=(v?.interfaces||[]).filter(x=>x.likely_vpn && interfaceIsUp(x));
  const ip=v?.public_ip||'не определён';
  $('#diagnostics-ip').textContent=ip;
  $('#diagnostics-geo').textContent=v?.public_geo||'внешний geo недоступен';
  $('#diagnostics-vpns').textContent=vpn.length?vpn.map(x=>x.name).join(', '):'не найдено';
  $('#diagnostics-interface-note').textContent=vpn.length?'активные VPN-интерфейсы':'подключите VPN перед запуском Tunnel';
  $('#diagnostics-dns-count').textContent=`${dns.length-suspicious}/${dns.length}`;
  $('#diagnostics-dns-note').textContent=suspicious?`${suspicious} подозрительных совпадений`:'system ↔ Cloudflare/Google DoH';
  summary.className='diagnostics-summary '+(suspicious?'bad':(vpn.length?'good':'warn'));
  summary.textContent=suspicious
    ? `DNS проверка завершена: ${suspicious} домен(ов) имеют расхождения с trusted DoH.`
    : `Проверено ${dns.length} домен(ов), ${v?.interfaces?.length||0} интерфейс(ов).`;

  const interfaces=(v?.interfaces||[]).filter(x=>x.flags?.includes('up') || x.likely_vpn);
  const interfaceRows=interfaces.map(x=>`<div class="diagnostic-row"><strong>${x.likely_vpn?'★ ':''}${esc(x.name)}</strong><span>${esc((x.flags||[]).join(', ')||'down')} · ${esc((x.addresses||[]).join(', ')||'без адреса')}</span></div>`).join('');
  const dnsRows=dns.map(x=>`<div class="diagnostic-row ${x.suspicious?'suspicious':''}"><strong>${esc(x.domain)}</strong><span>system ${esc((x.system||[]).join(', ')||'—')} · DoH ${esc(Array.from(new Set([...(x.cloudflare||[]),...(x.google||[])])).join(', ')||'—')}${x.suspicious?' · расхождение':''}</span></div>`).join('');
  $('#diagnostics-details').innerHTML=`<div class="diagnostic-list"><h3>Активные интерфейсы</h3>${interfaceRows||'<div class="diagnostic-empty">Интерфейсы не найдены.</div>'}</div><div class="diagnostic-list"><h3>DNS-сверка</h3>${dnsRows||'<div class="diagnostic-empty">DNS данные недоступны.</div>'}</div>`;
}

async function refreshDiagnostics(showError=false){
  const panel=$('#diagnostics-panel');
  const summary=$('#diagnostics-summary');
  panel?.classList.add('loading');
  if(summary) summary.textContent='Проверяю system DNS, trusted DoH и активные интерфейсы…';
  try{
    const value=await api('/api/diagnostics');
    renderDiagnostics(value);
    return value;
  }catch(e){
    panel?.classList.remove('loading');
    if(summary){ summary.className='diagnostics-summary bad'; summary.textContent=`Диагностика недоступна: ${e.message}`; }
    if(showError) throw e;
    return null;
  }
}

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
  // The supported default workflow is the persistent local proxy. Keep the
  // more elaborate tunnel indicators out of the normal setup path.
  setSetupStep('#setup-singbox', state.sing_box_path?'ready':'auto', state.sing_box_path?'READY':'AUTO');
  setSetupStep('#setup-vpn','ready','НЕ НУЖЕН');
  setSetupStep('#setup-privileges','ready','НЕ НУЖНЫ');
  setSetupStep('#setup-runtime',state.proxy_running?'ready':'auto',state.proxy_running?'ЗАПУЩЕН':'ГОТОВ');
  const simpleOverall=$('#setup-overall');
  if(simpleOverall){
    simpleOverall.classList.remove('ready','needs','active');
    simpleOverall.textContent=state.proxy_running?'PROXY READY':'ONE-CLICK READY';
    simpleOverall.classList.add(state.proxy_running?'active':'ready');
  }
  const simpleNote=$('#setup-note');
  if(simpleNote) simpleNote.textContent=state.proxy_running
    ? 'Proxy работает на 127.0.0.1:7890. TUN и системные proxy-настройки не изменяются.'
    : 'Запустите proxy одним нажатием; дополнительные права и VPN-интерфейс не требуются.';
}

async function refresh(){
  if(refreshInFlight) return;
  refreshInFlight=true;
  try{
  state=await api('/api/status');
  setMetric('#proxy-state',state.proxy_running?'ЗАПУЩЕН':'ВЫКЛЮЧЕН',state.proxy_running?'good':'');

  const tunnel=$('#tunnel-state');
  if(!state.agent_tunnel_supported){
    setMetric('#tunnel-state','НЕДОСТУПЕН','bad');
  }else if(state.agent_tunnel_active){
    setMetric('#tunnel-state','АКТИВЕН','good');
  }else{
    setMetric('#tunnel-state','ВЫКЛЮЧЕН','');
  }
  const enforcement=state.tunnel_enforcement||'userspace-soft';
  setMetric('#tunnel-enforcement', enforcement==='kernel-hard'?'KERNEL HARD':(enforcement==='userspace-soft'?'SOFT POLICY':'INACTIVE'), enforcement==='kernel-hard'?'good':(enforcement==='userspace-soft'?'warn':''));

  setMetric('#ag-state',state.antigravity_path?'найден':'не найден',state.antigravity_path?'good':'warn');
  $('#platform-state').textContent=`${state.os}/${state.arch}`;
  $('#proxy-url').textContent=state.proxy_url;
  const summary=$('#system-summary');
  if(summary){
    summary.className='system-summary';
    const journal=state.health?.dimensions?.network_journal;
    if(journal && !journal.ok){
      summary.classList.add('bad');
      summary.textContent='Требуется восстановление сетевого состояния. Запуск Tunnel заблокирован до успешной очистки.';
    }else if(enforcement==='kernel-hard'){
      summary.classList.add('good');
      summary.textContent='KERNEL HARD: Antigravity в отдельном namespace; выход разрешён только через выбранный VPN';
    }else if(state.agent_tunnel_active && state.health?.state==='healthy'){
      summary.classList.add('good');
      summary.textContent='Antigravity → выбранный VPN · остальные приложения → системный маршрут';
    }else if(state.proxy_running){
      summary.classList.add('good');
      summary.textContent='SAFE MODE: системные proxy-настройки не изменены';
    }else{
      summary.textContent='Системный маршрут не изменён. Выберите SAFE MODE или Agent Tunnel.';
    }
  }
  if($('#tunnel-hint')) $('#tunnel-hint').textContent=state.agent_tunnel_hint||'';

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
  renderPolicy();
  }finally{
    refreshInFlight=false;
  }
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
  stateEl.textContent=({verified:'ПОДТВЕРЖДЕНО',degraded:'ПРОБЛЕМА',partial:'ЧАСТИЧНО',idle:'ОЖИДАНИЕ'})[level]||level.toUpperCase();
  stateEl.style.color=assuranceColor(level);

  const isolation=String(v?.isolation||'inactive').toLowerCase();
  const isolationEl=$('#assurance-isolation');
  if(isolationEl){
    isolationEl.textContent=({strict:'СТРОГО','isolation-relaxed':'ОСЛАБЛЕНО',inactive:'ВЫКЛЮЧЕНО'})[isolation]||isolation.toUpperCase();
    isolationEl.style.color=isolationColor(isolation);
  }
  const isolationDetail=$('#assurance-isolation-detail');
  if(isolationDetail) isolationDetail.textContent=v?.isolation_detail||'';

  const active=v?.pid_route?.active_candidate_pids?.length||0;
  const vpn=v?.pid_route?.vpn_direct_pids?.length||0;
  const ambiguous=v?.pid_route?.ambiguous_connections||0;
  const pidEl=$('#assurance-pids');
  pidEl.textContent=active?`${vpn}/${active}${ambiguous?` · неоднозначных ${ambiguous}`:''}`:'—';
  pidEl.style.color=active && vpn===active && !ambiguous?'var(--good)':(ambiguous?'var(--bad)':'var(--muted)');

  const egressEl=$('#assurance-egress');
  if(v?.egress?.available){
    const count=v.egress.vpn_observed_ips?.length||0;
    egressEl.textContent=`ПОДТВЕРЖДЁН${count>1?` · ${count} IP`:''}`;
    egressEl.style.color='var(--good)';
  }else{
    egressEl.textContent='НЕТ ДАННЫХ';
    egressEl.style.color=level==='degraded'?'var(--bad)':'var(--muted)';
  }

  const ageEl=$('#assurance-age');
  if(v?.egress?.observed_at){
    const observed=new Date(v.egress.observed_at);
    const age=Math.max(0,Math.round((Date.now()-observed.getTime())/1000));
    const until=v.egress_fresh_until?new Date(v.egress_fresh_until):null;
    const left=until?Math.max(0,Math.ceil((until.getTime()-Date.now())/1000)):0;
    ageEl.textContent=`${v.egress_cached?'кэш':'свежий'} · ${age}с${until?` · TTL ${left}с`:''}`;
  }else{
    ageEl.textContent='—';
  }
  ageEl.style.color=v?.egress_cached?'var(--warn)':'var(--muted)';
  $('#assurance-detail').textContent=v?.detail||'Нет evidence.';
}

async function refreshAssurance(){
  if(assuranceInFlight) return;
  assuranceInFlight=true;
  try{
    renderAssurance(await api('/api/attestation'));
  }catch(e){
    const stateEl=$('#assurance-state');
    if(stateEl){
      stateEl.textContent='ERROR';
      stateEl.style.color='var(--bad)';
      $('#assurance-detail').textContent=e.message;
    }
  }finally{
    assuranceInFlight=false;
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

async function action(name){
  try{
    setBusy(true);
    let res;

    if(name==='refresh'){
      await Promise.all([refresh(),refreshAssurance(),refreshDiagnostics()]);
      return;
    }
    if(name==='clear-output'){
      setOutput('Готово.');
      return;
    }
    if(name==='clear-logs'){
      const ev=$('#events');
      if(ev) ev.innerHTML='';
      showToast('События очищены', 'good');
      return;
    }
    if(name==='attestation'){
      res=await api('/api/attestation');
      renderAssurance(res);
    }else if(name==='save-config'){
      res=await saveConfigFromUI();
      showToast('Настройки сохранены', 'good');
      const saveStatus=$('#save-status');
      if(saveStatus){ saveStatus.textContent='Сохранено'; saveStatus.classList.remove('error'); setTimeout(()=>{saveStatus.textContent='';},3000); }
    }else if(name==='diagnostics'){
      res=await refreshDiagnostics(true);
      showToast('Диагностика обновлена', 'good');
    }else if(name==='agent-doctor'){
      res=await api('/api/agent-doctor');
    }else if(name==='logs'){
      res=await api('/api/logs');
    }else{
      const path=name
        .replace('hosts-enable','hosts/enable')
        .replace('hosts-disable','hosts/disable');
      res=await api('/api/actions/'+path,{method:'POST'});
      showToast(`Команда выполнена: ${name}`, 'good');
    }

    setOutput(res);
    await Promise.all([refresh(),refreshAssurance()]);
  }catch(e){
    const message=String(e?.message||e||'unknown error');
    setOutput('ERROR\n'+message);
    showToast(`Ошибка: ${message}`, 'bad');
    const saveStatus=$('#save-status');
    if(name==='save-config' && saveStatus){ saveStatus.textContent='Не сохранено'; saveStatus.classList.add('error'); }
  }finally{
    setBusy(false);
  }
}

document.addEventListener('click', async e=>{
  const b=e.target.closest('[data-action]');
  if(b) return action(b.dataset.action);

  if(e.target?.id==='copy-proxy-btn'){
    const url=state?.proxy_url||$('#proxy-url')?.textContent||'http://127.0.0.1:7890';
    try{
      await navigator.clipboard.writeText(url);
      showToast(`Скопировано: ${url}`, 'good');
    }catch{
      showToast('Не удалось скопировать URL в буфер', 'bad');
    }
    return;
  }

  if(e.target?.id==='copy-env-btn'){
    const url=state?.proxy_url||$('#proxy-url')?.textContent||'http://127.0.0.1:7890';
    const cmd=`export all_proxy=${url} http_proxy=${url} https_proxy=${url}`;
    try{
      await navigator.clipboard.writeText(cmd);
      showToast('export команды скопированы в буфер', 'good');
    }catch{
      showToast('Не удалось скопировать команду в буфер', 'bad');
    }
    return;
  }

  const pill=e.target.closest('#log-filters .pill');
  if(pill){
    document.querySelectorAll('#log-filters .pill').forEach(p=>p.classList.remove('active'));
    pill.classList.add('active');
    const filter=pill.dataset.filter;
    const ev=$('#events');
    if(ev){
      ev.classList.remove('filter-error','filter-warn','filter-info');
      if(filter && filter!=='all') ev.classList.add('filter-'+filter);
    }
  }
});

document.addEventListener('change',e=>{
  if(e.target?.id==='vpn-interface'){
    const v=e.target.value;
    const info=(state?.interfaces||[]).find(i=>i.name===v);
    const help=$('#vpn-help');
    if(help) help.textContent=info?`${info.flags?.includes('up')?'Активен':'DOWN'} · ${(info.addresses||[]).join(', ')}`:'Автоматический выбор будет выполнен при запуске Tunnel.';
  }
  if(e.target?.id==='tunnel-domain-fallback') renderPolicy();
});

function connectEvents(){
  const es=new EventSource('/api/events');
  es.onopen=()=>{
    $('#live-dot').classList.add('on');
    $('#live-text').textContent='связь активна';
  };
  es.onerror=()=>{
    $('#live-dot').classList.remove('on');
    $('#live-text').textContent='переподключение…';
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
Promise.all([refresh(),refreshAssurance(),refreshDiagnostics()]).catch(e=>setOutput(e.message));
connectEvents();
setInterval(()=>{
  refresh().catch(()=>{});
  refreshAssurance().catch(()=>{});
},5000);
