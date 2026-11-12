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
    .diag{margin-top:9px;border:1px solid #e2e8f0;border-radius:8px;padding:10px}.diag h3{margin-top:0}
    .finding{margin:4px 0;padding:6px 8px;border-radius:6px;background:#f8fafc}.finding.error{background:#fef2f2}.finding.warning{background:#fffbeb}.finding.ok{background:#f0fdf4;color:#166534}
    details{border-top:1px solid #e2e8f0;padding:6px 0}summary{cursor:pointer;font-weight:650}ul{margin:4px 0 4px 18px;padding:0}
    .recorded{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;background:#f1f5f9;padding:4px 6px;border-radius:5px;white-space:pre-wrap;word-break:break-word}
    @media(max-width:480px){.grid{grid-template-columns:1fr}}
  `;
  shadow.appendChild(style);
  const launch = element('button', { id: 'launch', text: 'Okta diagnostics' });
  launch.setAttribute('aria-label','Open Okta diagnostics');
  launch.setAttribute('aria-expanded','false');
  launch.setAttribute('aria-controls','panel');
  shadow.appendChild(launch);
  const panel = element('section',{id:'panel'});
  panel.hidden = true;
  panel.setAttribute('role','region');
  panel.setAttribute('aria-label','Okta Diagnostics Companion');
  shadow.appendChild(panel);
  launch.addEventListener('click', openPanel);
  // Shadow DOM uses page styles minimally. Never insert untrusted API data as HTML.
  const head=element('header');
  head.appendChild(element('h2',{text:'Okta Diagnostics Companion'}));
  const close=element('button',{text:'Close'});
  close.addEventListener('click',closePanel);
  panel.addEventListener('keydown',e=>{if(e.key==='Escape'){e.stopPropagation();closePanel();}});
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
  const msg=element('p',{id:'status',className:'muted',text:'Searches bounded user log events by actor and target. Results are limited to 3 pages per query (up to 600 before deduplication).'});panel.appendChild(msg);
  const info=element('div',{className:'summary',text:'Enter an Okta user ID or login to begin.'});panel.appendChild(info);
  const stats=element('div',{className:'stats'});panel.appendChild(stats);
  const hints=element('div',{className:'summary',text:'Diagnostic hints appear here when supported by failed or denied events.'});panel.appendChild(hints);
  const diag=element('section',{className:'diag'});diag.setAttribute('aria-label','Provisioning diagnosis');diag.hidden=true;panel.appendChild(diag);
  const scroll=element('div',{className:'scroll'});panel.appendChild(scroll);
  msg.setAttribute('role','status');msg.setAttribute('aria-live','polite');
  let displayed=[];

  run.addEventListener('click',async()=>{
    run.disabled=true;exportButton.disabled=true;displayed=[];clear(stats);clear(scroll);clear(diag);diag.hidden=true;hints.textContent='Analyzing…';
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
      let appUser=null;
      if(appId){
        try {
          appUser=await getJson(`/api/v1/apps/${encodeURIComponent(appId)}/users/${encodeURIComponent(user.id)}`);
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
      renderDiagnosis(core.diagnoseProvisioning(displayed,appUser),diag);
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

  function openPanel(){launch.hidden=true;launch.setAttribute('aria-expanded','true');panel.hidden=false;userInput.focus();}
  function closePanel(){panel.hidden=true;launch.hidden=false;launch.setAttribute('aria-expanded','false');launch.focus();}
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
  function renderDiagnosis(d,target){
    if(!d.attempts.length && !d.appUserFindings.length)return;
    target.hidden=false;
    target.appendChild(element('h3',{text:'Provisioning diagnosis'}));
    const headline=d.failedAttempts
      ? `${d.failedAttempts} of ${d.attempts.length} provisioning attempt(s) failed. Most recent failure: ${d.lastFailure}.`
      : `${d.attempts.length} provisioning attempt(s) found with no recorded failure.`;
    target.appendChild(element('p',{text:headline}));
    if(d.recoveredAt)target.appendChild(element('p',{className:'finding ok',text:`A later provisioning attempt succeeded at ${d.recoveredAt}. Earlier failures may already be resolved; confirm in the app.`}));
    for(const f of d.appUserFindings)target.appendChild(element('p',{className:'finding '+f.level,text:f.text}));
    const failed=d.attempts.filter(a=>a.failed).slice(0,10);
    if(d.failedAttempts>failed.length)target.appendChild(element('p',{className:'muted',text:`Showing the 10 most recent of ${d.failedAttempts} failed attempts.`}));
    failed.forEach((a,i)=>{
      const box=element('details');if(i===0)box.open=true;
      box.appendChild(element('summary',{text:`${a.last}${a.app?' · '+a.app:''} · ${a.causes.map(c=>c.title).join('; ')}`}));
      box.appendChild(element('p',{className:'muted tiny',text:`Transaction ${a.transactionId}${a.transactionType?' ('+a.transactionType+')':''} · events: ${a.eventTypes.join(', ')}`}));
      for(const c of a.causes){
        box.appendChild(element('p',{text:'Why: '+c.why}));
        const ul=element('ul');for(const step of c.checks)ul.appendChild(element('li',{text:step}));
        box.appendChild(element('p',{text:'What to check:'}));box.appendChild(ul);
        for(const ev of c.evidence.slice(0,3)){
          box.appendChild(element('p',{className:'muted tiny',text:`${ev.published} · ${ev.eventType}${ev.eventId?' · event '+ev.eventId:''}`}));
          box.appendChild(element('div',{className:'recorded',text:ev.recorded ? 'Okta recorded: '+ev.recorded : 'Okta recorded no error text for this event.'}));
        }
      }
      target.appendChild(box);
    });
    target.appendChild(element('p',{className:'muted tiny',text:'Causes are matched from error text Okta recorded. Confirm in the application before changing configuration.'}));
  }
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
  function apiError(response,label){
    const status=response.status;
    if(status===429){
      const reset=Number(response.headers.get('X-Rate-Limit-Reset'));
      const wait=Number.isFinite(reset)&&reset>0?Math.max(0,Math.ceil(reset-Date.now()/1000)):null;
      return new Error(`${label} rate limit reached (HTTP 429). Wait${wait!==null?` about ${wait}s`:' a minute'} and retry, or narrow the time window.`);
    }
    if(status===401||status===403)return new Error(`${label} HTTP ${status}: your current admin session or role is not authorized for this request.`);
    if(status===404)return new Error(`${label} HTTP 404: the requested user or app was not found or is not visible to your role.`);
    return new Error(`${label} HTTP ${status}`);
  }
  async function getJson(path){
    const response=await fetch(path,{method:'GET',credentials:'same-origin',headers:{Accept:'application/json'},redirect:'error'});
    if(!response.ok)throw apiError(response,'Okta API');
    return response.json();
  }
  async function getLogPage(url){
    const target=new URL(url);
    if(target.origin!==location.origin||target.pathname!=='/api/v1/logs')throw new Error('Refused unexpected API target.');
    const response=await fetch(target.href,{method:'GET',credentials:'same-origin',headers:{Accept:'application/json'},redirect:'error'});
    if(!response.ok)throw apiError(response,'System Log API');
    return {events:await response.json(),link:response.headers.get('Link')};
  }
})();
