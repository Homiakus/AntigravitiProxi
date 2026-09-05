const $ = s => document.querySelector(s);
const csrf = () => document.cookie.split('; ').find(x=>x.startsWith('agp_csrf='))?.split('=')[1] || '';
const output = $('#output');
let state = null;
let assurance = null;

function pretty(v){ return typeof v === 'string' ? v : JSON.stringify(v,null,2); }
function setOutput(v){ output.textContent = pretty(v); output.scrollTop = 0; }
function setBusy(on){ document.querySelectorAll('button').forEach(b=>b.disabled=on); }

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
  if(!r.ok) throw new Error(typeof data==='string' ? data : (data.error||JSON.stringify(data)));
  return data;
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
  if($('#tunnel-hint')) $('#tunnel-hint').textContent=state.agent_tunnel_hint||'';

  const sel=$('#vpn-interface');
  const current=state.settings.vpn_interface||'';
  sel.innerHTML='<option value="">Auto / current route</option>'+state.interfaces.map(i=>`<option value="${esc(i.name)}" ${i.name===current?'selected':''}>${i.likely_vpn?'★ ':''}${esc(i.name)} — ${esc(i.addresses.join(', '))}</option>`).join('');
  $('#dns-provider').value=state.settings.dns_provider||'cloudflare';
  $('#proxy-port').value=state.settings.proxy_port||7890;
  $('#auto-open').checked=!!state.settings.auto_open;
}

function assuranceColor(v){
  if(v==='verified') return 'var(--good)';
  if(v==='degraded') return 'var(--bad)';
  if(v==='partial') return 'var(--warn)';
  return 'var(--muted)';
}

function renderAssurance(v){
  assurance=v;
  const stateEl=$('#assurance-state');
  if(!stateEl) return;
  const level=String(v?.state||'idle').toLowerCase();
  stateEl.textContent=level.toUpperCase();
  stateEl.style.color=assuranceColor(level);

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

function esc(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function action(name){
  try{
    setBusy(true);
    let res;

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
      res=await api('/api/config',{method:'POST',body:{
        vpn_interface:$('#vpn-interface').value,
        dns_provider:$('#dns-provider').value,
        proxy_port:Number($('#proxy-port').value),
        auto_open:$('#auto-open').checked
      }});
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

    setOutput(res);
    await Promise.all([refresh(),refreshAssurance()]);
  }catch(e){
    setOutput('ERROR\n'+e.message);
  }finally{
    setBusy(false);
  }
}

document.addEventListener('click',e=>{
  const b=e.target.closest('[data-action]');
  if(b) action(b.dataset.action);
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
