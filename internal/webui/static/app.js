const $ = s => document.querySelector(s);
const csrf = () => document.cookie.split('; ').find(x=>x.startsWith('agp_csrf='))?.split('=')[1] || '';
const output = $('#output');
let state = null;

function pretty(v){ return typeof v === 'string' ? v : JSON.stringify(v,null,2); }
function setOutput(v){ output.textContent = pretty(v); output.scrollTop = 0; }
function setBusy(on){ document.querySelectorAll('button').forEach(b=>b.disabled=on); }
async function api(path, opts={}){
  const init = {...opts, headers:{...(opts.headers||{})}};
  if((init.method||'GET')!=='GET') init.headers['X-AGP-CSRF']=csrf();
  if(init.body && typeof init.body !== 'string'){ init.headers['Content-Type']='application/json'; init.body=JSON.stringify(init.body); }
  const r = await fetch(path,init); const text=await r.text(); let data=text; try{data=JSON.parse(text)}catch{}
  if(!r.ok) throw new Error(typeof data==='string'?data:(data.error||JSON.stringify(data)));
  return data;
}
async function refresh(){
  state=await api('/api/status');
  $('#proxy-state').textContent=state.proxy_running?'RUNNING':'OFF'; $('#proxy-state').style.color=state.proxy_running?'var(--good)':'var(--muted)';
  $('#singbox-state').textContent=state.sing_box_path?state.sing_box_version||'installed':'not installed';
  $('#ag-state').textContent=state.antigravity_path?'found':'not found';
  $('#platform-state').textContent=`${state.os}/${state.arch}`;
  $('#proxy-url').textContent=state.proxy_url;
  const sel=$('#vpn-interface'); const current=state.settings.vpn_interface||''; sel.innerHTML='<option value="">Auto / current route</option>'+state.interfaces.map(i=>`<option value="${esc(i.name)}" ${i.name===current?'selected':''}>${i.likely_vpn?'★ ':''}${esc(i.name)} — ${esc(i.addresses.join(', '))}</option>`).join('');
  $('#dns-provider').value=state.settings.dns_provider||'cloudflare'; $('#proxy-port').value=state.settings.proxy_port||7890; $('#auto-open').checked=!!state.settings.auto_open;
}
function esc(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function action(name){
  try{
    setBusy(true);
    let res;
    if(name==='refresh'){ await refresh(); return; }
    if(name==='clear-output'){ setOutput('Готово.'); return; }
    if(name==='save-config'){
      res=await api('/api/config',{method:'POST',body:{vpn_interface:$('#vpn-interface').value,dns_provider:$('#dns-provider').value,proxy_port:Number($('#proxy-port').value),auto_open:$('#auto-open').checked}});
    } else if(name==='diagnostics') res=await api('/api/diagnostics');
    else if(name==='logs') res=await api('/api/logs');
    else res=await api('/api/actions/'+name.replace('hosts-enable','hosts/enable').replace('hosts-disable','hosts/disable'),{method:'POST'});
    setOutput(res); await refresh();
  }catch(e){ setOutput('ERROR\n'+e.message); }
  finally{ setBusy(false); }
}
document.addEventListener('click',e=>{const b=e.target.closest('[data-action]');if(b)action(b.dataset.action)});

function connectEvents(){
  const es=new EventSource('/api/events');
  es.onopen=()=>{$('#live-dot').classList.add('on');$('#live-text').textContent='live'};
  es.onerror=()=>{$('#live-dot').classList.remove('on');$('#live-text').textContent='reconnect…'};
  es.onmessage=e=>{try{const v=JSON.parse(e.data);const row=document.createElement('div');row.className='event '+v.level;const t=new Date(v.time);row.innerHTML=`<span class="time">${t.toLocaleTimeString()}</span><span class="level">${esc(v.level)}</span><span>${esc(v.message)}</span>`;$('#events').prepend(row);while($('#events').children.length>250)$('#events').lastChild.remove()}catch{}};
}
if('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(()=>{});
refresh().catch(e=>setOutput(e.message)); connectEvents(); setInterval(()=>refresh().catch(()=>{}),5000);
