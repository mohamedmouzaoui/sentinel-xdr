import React, { useState, useEffect } from 'react';
import { incidentsService, reportsService } from '../services/api';
import { Layers, Clock, Target, AlertCircle, CheckCircle2, ChevronRight, Download, MessageSquare, User } from 'lucide-react';

const T = { bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230', bd1:'#1d2533', bd2:'#2a3445', br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85', crit:'#ff5c7c', critBg:'#ff5c7c18', high:'#ff9544', highBg:'#ff95441a', med:'#fbbf24', medBg:'#fbbf241a', low:'#3ddc97', lowBg:'#3ddc971a', ml:'#c084fc' };

const STATUS_FLOW = ['NEW','TRIAGED','IN_PROGRESS','CONTAINED','RESOLVED','CLOSED'];
const STATUS_COLORS = { NEW:'#ff5c7c', TRIAGED:'#ff9544', IN_PROGRESS:'#fbbf24', CONTAINED:'#22d3ee', RESOLVED:'#3ddc97', CLOSED:'#5d6d85', FALSE_POSITIVE:'#c084fc' };

const MOCK_INCIDENTS = [
  { id:18, title:'Multi-Stage Attack: SSH Brute Force → Lateral Movement → Credential Harvest', severity:'CRITICAL', status:'IN_PROGRESS', score:97, source_ip:'45.33.22.11', target_hostname:'dc01', kill_chain_phase:'Lateral Movement', mitre_tactics:['Credential Access','Lateral Movement','Defense Evasion'], mitre_techniques:['T1110','T1550','T1562'], assigned_to:1, sla_breached:false, sla_deadline:new Date(Date.now()+1000*60*8).toISOString(), mttd_seconds:480, mttr_seconds:null, created_at:new Date(Date.now()-1000*60*72).toISOString(), alert_count:7 },
  { id:17, title:'Anomalous DNS Beacon — Possible C2 Communication to evil-c2.net', severity:'HIGH', status:'TRIAGED', score:78, source_ip:'10.0.4.22', target_hostname:'WEB-02', kill_chain_phase:'Command and Control', mitre_tactics:['Command and Control'], mitre_techniques:['T1071'], assigned_to:null, sla_breached:false, sla_deadline:new Date(Date.now()+1000*60*42).toISOString(), mttd_seconds:null, mttr_seconds:null, created_at:new Date(Date.now()-1000*60*40).toISOString(), alert_count:2 },
  { id:16, title:'Ransomware Precursor Activity — Shadow Copy Deletion', severity:'CRITICAL', status:'RESOLVED', score:99, source_ip:'10.0.5.99', target_hostname:'FILESERVER-01', kill_chain_phase:'Impact', mitre_tactics:['Impact'], mitre_techniques:['T1490'], assigned_to:1, sla_breached:false, sla_deadline:new Date(Date.now()-1000*60*200).toISOString(), mttd_seconds:900, mttr_seconds:7200, created_at:new Date(Date.now()-1000*3600*12).toISOString(), alert_count:12 },
];

const MOCK_EVENTS = [
  { id:1, event_type:'STATUS_CHANGE', title:'Status changed: NEW → TRIAGED', username:'admin', body:null, metadata:{old_status:'NEW',new_status:'TRIAGED'}, created_at:new Date(Date.now()-1000*60*60).toISOString() },
  { id:2, event_type:'ASSIGNMENT', title:'Assigned to analyst #1', username:'admin', body:'L2 on call, please investigate SSH brute force origin', metadata:{assignee_id:1}, created_at:new Date(Date.now()-1000*60*55).toISOString() },
  { id:3, event_type:'STATUS_CHANGE', title:'Status changed: TRIAGED → IN_PROGRESS', username:'analyst.l2', body:null, metadata:{}, created_at:new Date(Date.now()-1000*60*40).toISOString() },
  { id:4, event_type:'COMMENT', title:'Analyst note', username:'analyst.l2', body:'Confirmed lateral movement. Source WKSTN-105 compromised. Running forensic dump playbook now.', metadata:{}, created_at:new Date(Date.now()-1000*60*25).toISOString() },
];

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState(MOCK_INCIDENTS);
  const [selected, setSelected] = useState(null);
  const [events, setEvents] = useState([]);
  const [newStatus, setNewStatus] = useState('');
  const [newComment, setNewComment] = useState('');
  const [reason, setReason] = useState('');
  const [statusModal, setStatusModal] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    incidentsService.list({ limit:50 }).then(r => setIncidents(r.data)).catch(() => {});
  }, []);

  const openDetail = async (inc) => {
    setSelected(inc);
    try {
      const { data } = await incidentsService.get(inc.id);
      setEvents(data.events || MOCK_EVENTS);
    } catch { setEvents(MOCK_EVENTS); }
  };

  const updateStatus = async () => {
    if (!newStatus || !selected) return;
    setLoading(true);
    try { await incidentsService.updateStatus(selected.id, newStatus, reason, newComment); } catch {}
    setIncidents(prev => prev.map(i => i.id===selected.id ? {...i, status:newStatus} : i));
    setSelected(s => s ? {...s, status:newStatus} : null);
    setEvents(prev => [{id:Date.now(), event_type:'STATUS_CHANGE', title:`Status changed: ${selected.status} → ${newStatus}`, username:'you', body:newComment||null, metadata:{}, created_at:new Date().toISOString()}, ...prev]);
    setStatusModal(false); setNewStatus(''); setReason(''); setNewComment('');
    setLoading(false);
  };

  const addComment = async () => {
    if (!newComment.trim() || !selected) return;
    try { await incidentsService.addComment(selected.id, newComment); } catch {}
    setEvents(prev => [{ id:Date.now(), event_type:'COMMENT', title:'Analyst note', username:'you', body:newComment, metadata:{}, created_at:new Date().toISOString() }, ...prev]);
    setNewComment('');
  };

  const exportPdf = async (id) => {
    try {
      const { data } = await reportsService.incidentPdf(id);
      const url = URL.createObjectURL(new Blob([data],{type:'application/pdf'}));
      const a = document.createElement('a'); a.href=url; a.download=`incident_${id}.pdf`; a.click(); URL.revokeObjectURL(url);
    } catch { alert('Backend offline — PDF unavailable'); }
  };

  return (
    <div style={{ display:'flex', height:'calc(100vh - 56px)', overflow:'hidden', fontFamily:'Inter, sans-serif', color:T.tx1 }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@700&family=JetBrains+Mono:wght@400;500&display=swap'); @keyframes slide-left{from{transform:translateX(20px);opacity:0}to{transform:translateX(0);opacity:1}} .evt-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px}`}</style>

      {/* List */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        <div style={{ padding:'16px 24px', borderBottom:`1px solid ${T.bd1}`, background:T.bg1 }}>
          <h1 style={{ margin:0, fontFamily:'Space Grotesk', fontSize:22, fontWeight:700 }}>Incidents</h1>
          <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:11, marginTop:4 }}>SOC Workflow · SLA Tracking · MTTD/MTTR</div>
        </div>
        <div style={{ flex:1, overflowY:'auto', padding:'8px 0' }}>
          {incidents.map(inc => {
            const sc = STATUS_COLORS[inc.status] || T.tx2;
            const slaDeadline = inc.sla_deadline ? new Date(inc.sla_deadline) : null;
            const slaLeft = slaDeadline ? Math.max(0, Math.round((slaDeadline - Date.now()) / 60000)) : null;
            const sevC = inc.severity==='CRITICAL'?T.crit:inc.severity==='HIGH'?T.high:inc.severity==='MEDIUM'?T.med:T.low;
            return (
              <div key={inc.id} onClick={() => openDetail(inc)} style={{ margin:'4px 16px', padding:'14px 16px', background:selected?.id===inc.id?T.bg3:T.bg1, border:`1px solid ${selected?.id===inc.id?T.bd2:T.bd1}`, borderRadius:6, cursor:'pointer', borderLeft:`3px solid ${sevC}` }}>
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:8 }}>
                  <div style={{ flex:1 }}>
                    <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>INC-{inc.id} · </span>
                    <span style={{ fontFamily:'Space Grotesk', fontSize:11, fontWeight:700, color:sc, background:`${sc}20`, padding:'2px 7px', borderRadius:3, letterSpacing:'0.04em' }}>{inc.status.replace('_',' ')}</span>
                  </div>
                  <div style={{ display:'flex', gap:6, alignItems:'center' }}>
                    <span style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:sevC }}>{inc.severity}</span>
                    {slaLeft !== null && slaLeft < 30 && !['RESOLVED','CLOSED'].includes(inc.status) && (
                      <span style={{ fontFamily:'JetBrains Mono', color:slaLeft<10?T.crit:T.high, fontSize:10, background:slaLeft<10?T.critBg:T.highBg, padding:'2px 6px', borderRadius:3 }}>
                        ⏱ SLA {slaLeft}m
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ color:T.tx1, fontSize:13, fontWeight:500, lineHeight:1.4, marginBottom:8 }}>{inc.title}</div>
                <div style={{ display:'flex', gap:16, fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>
                  {inc.source_ip && <span>src: {inc.source_ip}</span>}
                  <span>{inc.kill_chain_phase}</span>
                  <span>{inc.alert_count} alerts</span>
                  {inc.mttd_seconds && <span>MTTD {Math.round(inc.mttd_seconds/60)}m</span>}
                  {inc.mttr_seconds && <span>MTTR {Math.round(inc.mttr_seconds/60)}m</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div style={{ width:400, background:T.bg1, borderLeft:`1px solid ${T.bd1}`, display:'flex', flexDirection:'column', animation:'slide-left 0.2s ease-out' }}>
          {/* Header */}
          <div style={{ padding:'14px 18px', borderBottom:`1px solid ${T.bd1}`, display:'flex', justifyContent:'space-between', alignItems:'center', flexShrink:0 }}>
            <span style={{ fontFamily:'Space Grotesk', color:T.tx1, fontWeight:700, fontSize:14 }}>INC-{selected.id}</span>
            <div style={{ display:'flex', gap:6 }}>
              <button onClick={() => exportPdf(selected.id)} title="Export PDF" style={iBtn(T.br1)}><Download size={12}/></button>
              <button onClick={() => setStatusModal(true)} title="Change Status" style={iBtn(T.med)}><AlertCircle size={12}/></button>
              <button onClick={()=>setSelected(null)} style={{ background:'none', border:'none', color:T.tx3, cursor:'pointer', fontSize:16 }}>×</button>
            </div>
          </div>

          <div style={{ flex:1, overflowY:'auto', padding:18, display:'flex', flexDirection:'column', gap:14 }}>
            {/* Status flow */}
            <div style={{ display:'flex', gap:2, alignItems:'center' }}>
              {STATUS_FLOW.map((s, i) => {
                const idx = STATUS_FLOW.indexOf(selected.status);
                const done = i < idx; const active = i === idx;
                return (
                  <React.Fragment key={s}>
                    <div style={{ flex:1, textAlign:'center' }}>
                      <div style={{ height:3, background:done||active?STATUS_COLORS[s]:T.bd2, borderRadius:2, marginBottom:4, transition:'background 0.3s' }}/>
                      <div style={{ fontFamily:'Space Grotesk', fontSize:8, color:active?STATUS_COLORS[s]:done?T.tx3:T.bd2, fontWeight:active?700:400, letterSpacing:'0.04em' }}>{s.slice(0,3)}</div>
                    </div>
                    {i < STATUS_FLOW.length-1 && <div style={{ width:6, height:1, background:T.bd2, flexShrink:0 }}/>}
                  </React.Fragment>
                );
              })}
            </div>

            {/* Meta */}
            <div style={{ background:T.bg2, borderRadius:6, padding:12, fontFamily:'JetBrains Mono', fontSize:11, display:'flex', flexDirection:'column', gap:7 }}>
              {[
                ['Severity', selected.severity], ['Score', `${selected.score}/100`],
                ['Source IP', selected.source_ip||'—'], ['Target', selected.target_hostname||'—'],
                ['Kill Chain', selected.kill_chain_phase||'—'],
                ['Assigned To', selected.assigned_to ? `Analyst #${selected.assigned_to}` : 'Unassigned'],
                ['MTTD', selected.mttd_seconds ? `${Math.round(selected.mttd_seconds/60)} min` : '—'],
                ['MTTR', selected.mttr_seconds ? `${Math.round(selected.mttr_seconds/60)} min` : 'Ongoing'],
              ].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', gap:8 }}>
                  <span style={{ color:T.tx3 }}>{k}</span>
                  <span style={{ color:T.tx1 }}>{v}</span>
                </div>
              ))}
            </div>

            {/* MITRE */}
            {selected.mitre_techniques?.length > 0 && (
              <div>
                <div style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.08em', marginBottom:6 }}>MITRE ATT&CK</div>
                <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
                  {selected.mitre_techniques.map(t => (
                    <span key={t} style={{ fontFamily:'JetBrains Mono', color:T.ml, background:`${T.ml}20`, fontSize:10, padding:'3px 7px', borderRadius:3 }}>{t}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Timeline */}
            <div>
              <div style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.08em', marginBottom:8 }}>TIMELINE</div>
              <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
                {events.map(ev => {
                  const evC = ev.event_type==='STATUS_CHANGE'?T.br1:ev.event_type==='COMMENT'?T.med:ev.event_type==='ASSIGNMENT'?T.high:T.tx3;
                  return (
                    <div key={ev.id} style={{ display:'flex', gap:10 }}>
                      <div className="evt-dot" style={{ background:evC }}/>
                      <div style={{ flex:1 }}>
                        <div style={{ display:'flex', justifyContent:'space-between', gap:8, marginBottom:2 }}>
                          <span style={{ color:T.tx1, fontSize:12, fontWeight:500 }}>{ev.title}</span>
                          <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:9, flexShrink:0 }}>{new Date(ev.created_at).toISOString().slice(11,16)}</span>
                        </div>
                        <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10, marginBottom:2 }}>{ev.username}</div>
                        {ev.body && <div style={{ color:T.tx2, fontSize:11, fontStyle:'italic', lineHeight:1.4, background:T.bg2, padding:'6px 8px', borderRadius:4 }}>"{ev.body}"</div>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Add comment */}
            <div>
              <textarea value={newComment} onChange={e=>setNewComment(e.target.value)} rows={2} placeholder="Add analyst note..." style={{ width:'100%', background:T.bg0, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'8px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none', resize:'vertical', boxSizing:'border-box' }}/>
              <button onClick={addComment} style={{ marginTop:6, background:T.br1, border:'none', color:T.bg0, padding:'6px 14px', borderRadius:4, cursor:'pointer', fontSize:11, fontFamily:'Space Grotesk', fontWeight:700, letterSpacing:'0.06em' }}>ADD NOTE</button>
            </div>
          </div>
        </div>
      )}

      {/* Status modal */}
      {statusModal && selected && (
        <div style={{ position:'fixed', inset:0, background:'#00000090', display:'grid', placeItems:'center', zIndex:1000 }}>
          <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:10, padding:24, width:380 }}>
            <h3 style={{ margin:'0 0 14px', fontFamily:'Space Grotesk', color:T.tx1 }}>Change Incident Status</h3>
            <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
              {STATUS_FLOW.filter(s=>s!==selected.status).map(s => (
                <button key={s} onClick={()=>setNewStatus(s)} style={{ textAlign:'left', padding:'10px 14px', background:newStatus===s?`${STATUS_COLORS[s]}20`:T.bg2, border:`1px solid ${newStatus===s?STATUS_COLORS[s]:T.bd1}`, borderRadius:4, color:STATUS_COLORS[s], fontFamily:'Space Grotesk', fontWeight:700, fontSize:12, cursor:'pointer', letterSpacing:'0.06em' }}>{s.replace('_',' ')}</button>
              ))}
              {newStatus && (
                <>
                  <textarea value={reason} onChange={e=>setReason(e.target.value)} rows={2} placeholder="Reason / note for audit trail..." style={{ background:T.bg0, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'8px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none', resize:'vertical' }}/>
                </>
              )}
              <div style={{ display:'flex', gap:8, justifyContent:'flex-end', marginTop:6 }}>
                <button onClick={()=>setStatusModal(false)} style={{ background:'transparent', border:`1px solid ${T.bd2}`, color:T.tx1, padding:'7px 14px', borderRadius:4, cursor:'pointer', fontSize:12 }}>Cancel</button>
                <button onClick={updateStatus} disabled={!newStatus||loading} style={{ background:newStatus?STATUS_COLORS[newStatus]:T.tx3, border:'none', color:T.bg0, padding:'7px 16px', borderRadius:4, cursor:'pointer', fontSize:12, fontFamily:'Space Grotesk', fontWeight:700 }}>Confirm</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function iBtn(color) {
  return { background:`${color}20`, border:`1px solid ${color}40`, color, padding:'5px 7px', borderRadius:4, cursor:'pointer', display:'grid', placeItems:'center' };
}
