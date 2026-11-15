'use strict';
let csrf = '', timer;
const el = id => document.getElementById(id);
const message = text => { el('message').textContent = text; };
async function api(path, data) {
  const response = await fetch(path, data === undefined ? {cache:'no-store'} : {
    method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) { const error = new Error(result.error || result.message || 'Request failed'); error.status = response.status; throw error; }
  return result;
}
function signedIn(yes) { el('login').hidden = yes; el('workspace').hidden = !yes; if (!yes) { clearTimeout(timer); csrf=''; el('evidence').textContent=''; el('findings').replaceChildren(); el('results').hidden=true; } }
function item(tag, text) { const node=document.createElement(tag); node.textContent=text; return node; }
function render(state) {
  csrf=state.csrf; el('status').textContent=state.status.toUpperCase(); el('start').disabled=state.status==='running';
  el('activity-note').textContent=state.status==='running' ? 'Live audit in progress. Only validated tool activity is shown.' : 'Activity from this server session. Completion is not proof of Internet reachability.';
  el('events').replaceChildren(...state.events.map(e=>item('li',`Turn ${e.turn} · ${e.tool} · ${e.decision} / ${e.status}`)));
  const report=state.report; el('results').hidden=!report;
  if (!report) return;
  el('result-note').textContent=report.failure || `${report.mode} · ${report.status} · ${report.generated_at} · ${report.llm_model}`;
  el('findings').replaceChildren();
  for (const finding of report.findings || []) {
    const card=item('article',''); card.append(item('h3',`${finding.severity}: ${finding.title}`),item('p',finding.impact),item('p',`Recommendation: ${finding.recommendation}`));
    for (const evidence of finding.evidence || []) card.append(item('p',`Evidence: ${evidence.observation_id} ${evidence.pointer}`));
    for (const step of finding.verification_plan || []) card.append(item('p',`Suggested verification (not executed): ${step}`));
    el('findings').append(card);
  }
  if (report.findings && !report.findings.length) el('findings').append(item('p','No supported candidates were produced. This does not establish that the host is secure.'));
  el('coverage').replaceChildren(...(report.coverage_notes || []).map(x=>item('li',x)));
  el('evidence').textContent=JSON.stringify(report,null,2);
}
async function poll() {
  clearTimeout(timer);
  try { const state=await api('/api/state'); signedIn(true); render(state); timer=setTimeout(poll,1500); }
  catch(error) { if(error.status===401) signedIn(false); else {message('Cannot reach local HTTPS server. Check the launcher.');timer=setTimeout(poll,5000);} }
}
el('login-form').addEventListener('submit',async event=>{event.preventDefault();try{const result=await api('/api/login',{password:el('password').value});el('password').value='';csrf=result.csrf;message('Local session unlocked.');await poll();}catch(error){el('password').value='';message(error.message);}});
el('audit-form').addEventListener('submit',async event=>{event.preventDefault();el('start').disabled=true;try{const result=await api('/api/audit',{goal:el('goal').value});message(result.message);await poll();}catch(error){message(error.message);el('start').disabled=false;}});
el('logout').addEventListener('click',async()=>{try{await api('/api/logout',{});signedIn(false);message('Signed out. An already running bounded audit continues on the server.');}catch(error){message(error.message);}});
poll();
