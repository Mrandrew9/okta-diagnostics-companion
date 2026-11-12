/* Read-only Okta Admin companion. Runs locally, on the current Okta origin. */
(() => {
  'use strict';
  if (!/^\/admin(?:\/|$)/.test(location.pathname)) return;
  if (document.getElementById('odc-host')) return;
  const core = globalThis.OktaDiagnosticsCore;
  if (!core || location.protocol !== 'https:') return;

  const host = document.createElement('div');
  host.id = 'odc-host';
  const shadow = host.attachShadow({ mode: 'open' });
  document.documentElement.appendChild(host);

  const style = document.createElement('style');
  style.textContent = `
    :host{all:initial;position:fixed;right:18px;bottom:18px;z-index:2147483646;font:13px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#14213d}
    *{box-sizing:border-box}button,input,select{font:inherit}
    #launch{background:#172554;color:#fff;border:0;border-radius:18px;padding:11px 17px;cursor:pointer;box-shadow:0 3px 20px #0005}
    #panel{background:#fff;color:#172554;border:1px solid #dce3ef;width:min(580px,calc(100vw - 36px));max-height:min(82vh,760px);overflow:auto;border-radius:14px;box-shadow:0 12px 45px #0004;padding:17px}
    header{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:10px}
    h2{font-size:18px;margin:0} h3{font-size:14px;margin:10px 0 5px}
    button{border-radius:7px;padding:8px 10px;border:1px solid #cbd5e1;background:#f1f5f9;cursor:pointer;color:#172554}
    button.primary{background:#1e40af;color:#fff;border-color:#1e40af}button:disabled{opacity:.6;cursor:wait}
    label{font-size:12px;font-weight:650;display:block;margin-bottom:3px}
    input{width:100%;border:1px solid #cbd5e1;border-radius:7px;padding:8px;color:#172554;background:white}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.full{grid-column:1/-1}
    .row{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:10px}
    .muted{color:#52627a;font-size:12px}.warning{color:#92400e}.error{color:#b91c1c}
    .stats{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}.pill{border-radius:7px;background:#eff6ff;padding:6px 9px}
    .scroll{max-height:300px;overflow:auto;border:1px solid #e2e8f0;border-radius:7px}
    table{width:100%;border-collapse:collapse;font-size:11px}th,td{padding:6px;text-align:left;border-bottom:1px solid #e2e8f0;vertical-align:top}th{position:sticky;top:0;background:#f8fafc}
    .tiny{font-size:11px}.summary{background:#f8fafc;border:1px solid #e2e8f0;padding:10px;border-radius:8px;margin-top:9px;white-space:pre-wrap}
    @media(max-width:480px){.grid{grid-template-columns:1fr}}
  `;
  shadow.appendChild(style);
  const launch = element('button', { id: 'launch', text: 'Okta diagnostics' });
  launch.setAttribute('aria-label','Open Okta diagnostics');
  shadow.appendChild(launch);
  const panel = element('section',{id:'panel'});
  panel.hidden = true;
  shadow.appendChild(panel);
  launch.addEventListener('click', () => { launch.hidden = true; panel.hidden = false; });
  // Shadow DOM uses page styles minimally. Never insert untrusted API data as HTML.
  const head=element('header');
  head.appendChild(element('h2',{text:'Okta Diagnostics Companion'}));
  const close=element('button',{text:'Close'});
  close.addEventListener('click',()=>{panel.hidden=true;launch.hidden=false;});
  head.appendChild(close); panel.appendChild(head);
  panel.appendChild(element('p',{className:'muted',text:'Read-only, local browser analysis. Uses your current authorized Okta session. No API token is requested or stored.'}));
  const grid=element('div',{className:'grid'});panel.appendChild(grid);
  const userInput=addInput(grid,'User ID or login','user','e.g. user@example.com');
  const appInput=addInput(grid,'App ID (optional)','app','e.g. 0oa...');
  const sinceInput=addInput(grid,'Since (local time)','since',null,'datetime-local');
  const untilInput=addInput(grid,'Until (local time)','until',null,'datetime-local');
  const now=new Date();untilInput.value=localDateTime(now);sinceInput.value=localDateTime(new Date(now.getTime()-7*86400000));
  const actions=element('div',{className:'row'});panel.appendChild(actions);
  const run=element('button',{text:'Analyze user',className:'primary'});
  const exportButton=element('button',{text:'Export displayed CSV'});exportButton.disabled=true;
  actions.append(run,exportButton);
  const msg=element('p',{className:'muted',text:'Searches bounded user log events by actor and target. Results are limited to 3 pages per query (up to 600 before deduplication).'});panel.appendChild(msg);
  const info=element('div',{className:'summary',text:'Enter an Okta user ID or login to begin.'});panel.appendChild(info);
  const stats=element('div',{className:'stats'});panel.appendChild(stats);
  const hints=element('div',{className:'summary',text:'Diagnostic hints appear here when supported by failed or denied events.'});panel.appendChild(hints);
  const scroll=element('div',{className:'scroll'});panel.appendChild(scroll);
  let displayed=[];

  run.addEventListener('click',async()=>{
    run.disabled=true;exportButton.disabled=true;displayed=[];clear(stats);clear(scroll);hints.textContent='Analyzing…';
    try{
      const start=new Date(sinceInput.value),end=new Date(untilInput.value);
      core.validateWindow(start,end);
      const input=userInput.value.trim();
      if(!input || input.length>256)throw new Error('Enter one valid user ID or login (maximum 256 characters).');
      if(!/^[^\s\/<>{}]+$/.test(input)) throw new Error('User login contains invalid characters.');
      const appId=appInput.value.trim();if(appId)core.validateIdentifier(appId,'App ID');
      msg.className='muted'; msg.textContent='Looking up Okta user…';
      const user=await getJson('/api/v1/users/'+encodeURIComponent(input));
      core.validateIdentifier(user.id,'Resolved user ID');
      const resolved=String(user?.profile?.login || user.id);
      msg.textContent='Retrieving time-bounded System Log records…';
      const logs=await core.collectLogs({origin:location.origin,userId:user.id,since:start,until:end,requestPage:getLogPage,pagesPerFilter:3});
      const unfiltered=logs.events;
      displayed=appId ? unfiltered.filter(x=>core.matchesApp(x,appId)) : unfiltered;
      const s=core.summarize(displayed);
      const bits=[`User: ${resolved} · Okta status: ${user.status || 'unknown'}`,`Events returned: ${s.total} · failures: ${s.failures} · denials: ${s.denials}`];
      if(appId){
        try {
          const appUser=await getJson(`/api/v1/apps/${encodeURIComponent(appId)}/users/${encodeURIComponent(user.id)}`);
          bits.push(`App-user record: ${appUser.status || 'found (status not supplied)'}`);
        } catch(e) {
          bits.push(`App-user record: not confirmed (${e.message}).`);
        }
        bits.push('App filter only includes events that explicitly target this app; related events without an app target may be omitted.');
      }
      bits.push('Assignment or app-user presence does not prove downstream SCIM provisioning succeeded. Review corresponding System Log events.');
      if(logs.pageLimitHit)bits.push('Partial results: safety page limit reached. Narrow the time window for more complete coverage.');
      info.textContent=bits.join('\n');
      for(const [name,value] of Object.entries({Events:s.total,Failures:s.failures,Denials:s.denials,'Sign-ins':s.signIn,Provisioning:s.provisioning,Security:s.security})){
        stats.appendChild(element('span',{className:'pill',text:`${name}: ${value}`}));
      }
      const observedHints=core.triageHints(displayed);
      hints.textContent=observedHints.length ? 'Observed failure patterns (not definitive root causes):\n' + observedHints.map(h=>`• ${h.count} × ${h.eventType}: ${h.guidance}`).join('\n') : 'No pre-defined failure patterns detected in the returned events. Inspect individual event outcomes below.';
      renderTable(displayed,scroll);
      exportButton.disabled=displayed.length===0;
      msg.textContent='Report generated locally. A failed or denied event is an observed outcome, not an automatic root-cause determination.';
    }catch(e){hints.textContent='No diagnostic hints available.';msg.className='error';msg.textContent=`Could not complete diagnostics: ${e.message}`;info.textContent='If the API returns 401/403, check your Okta Admin login and role permissions. If the browser blocks requests, review tenant CORS/session settings; do not paste an API token into this extension.';}
    finally{run.disabled=false;}
  });

  exportButton.addEventListener('click',()=>{
    if(!displayed.length)return;
    const csv=core.toCsv(displayed);
    const blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;a.download='okta-user-diagnostics-'+new Date().toISOString().slice(0,10)+'.csv';
    document.documentElement.appendChild(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
    msg.className='warning';msg.textContent='CSV downloaded locally. Contains user/security metadata (including IP addresses). Store and share only through approved channels.';
  });

  function element(tag,{id,text,className}={}){
    const x=document.createElement(tag);if(id)x.id=id;if(text!==undefined)x.textContent=text;if(className)x.className=className;return x;
  }
  function addInput(parent,title,id,placeholder,type='text'){
    const wrapper=element('div');const label=element('label',{text:title});label.htmlFor='odc-'+id;
    const input=element('input',{id:'odc-'+id});input.type=type;if(placeholder)input.placeholder=placeholder;
    wrapper.append(label,input);parent.appendChild(wrapper);return input;
  }
  function localDateTime(d){const z=n=>String(n).padStart(2,'0');return `${d.getFullYear()}-${z(d.getMonth()+1)}-${z(d.getDate())}T${z(d.getHours())}:${z(d.getMinutes())}`;}
  function clear(node){while(node.firstChild)node.firstChild.remove();}
  function renderTable(events,target){
    if(!events.length){target.appendChild(element('p',{className:'muted',text:'No matching events in the returned pages. This does not prove no incident occurred.'}));return;}
    const table=element('table'),thead=element('thead'),tbody=element('tbody');
    const header=element('tr');for(const h of ['When','Type','Outcome','Description'])header.appendChild(element('th',{text:h}));thead.appendChild(header);
    for(const e of events){const row=core.rowFor(e),tr=element('tr');
      for(const val of [row.published,row.eventType,`${row.outcome}${row.reason?' · '+row.reason:''}`,row.message]){
        const td=element('td',{text:val});td.title=val;tr.appendChild(td);
      }tbody.appendChild(tr);
    }table.append(thead,tbody);target.appendChild(table);
  }
  async function getJson(path){
    const response=await fetch(path,{method:'GET',credentials:'same-origin',headers:{Accept:'application/json'},redirect:'error'});
    if(!response.ok)throw new Error(`Okta API HTTP ${response.status}`);
    return response.json();
  }
  async function getLogPage(url){
    const target=new URL(url);
    if(target.origin!==location.origin||target.pathname!=='/api/v1/logs')throw new Error('Refused unexpected API target.');
    const response=await fetch(target.href,{method:'GET',credentials:'same-origin',headers:{Accept:'application/json'},redirect:'error'});
    if(!response.ok)throw new Error(`System Log API HTTP ${response.status}`);
    return {events:await response.json(),link:response.headers.get('Link')};
  }
})();
