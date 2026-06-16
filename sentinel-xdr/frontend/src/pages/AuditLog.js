import React, { useState, useEffect } from 'react';
import { auditService } from '../services/api';
import { BookOpen, User, Shield, Clock, Download } from 'lucide-react';

const T = { bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bd1:'#1d2533', bd2:'#2a3445', br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85', crit:'#ff5c7c', high:'#ff9544', low:'#3ddc97', ml:'#c084fc' };

const ACTION_COLORS = {
  LOGIN:'#22d3ee', LOGOUT:'#5d6d85',
  INCIDENT_STATUS_CHANGE:'#fbbf24', INCIDENT_ASSIGN:'#ff9544',
  ALERT_ACK:'#3ddc97', ALERT_FP:'#c084fc',
  IOC_CREATE:'#22d3ee', IOC_UPDATE:'#ff9544', IOC_DELETE:'#ff5c7c',
  PLAYBOOK_EXECUTE:'#c084fc',
  RULE_ENABLE:'#3ddc97', RULE_DISABLE:'#ff5c7c',
};

const MOCK_LOGS = [
  { id:1, action:'INCIDENT_STATUS_CHANGE', resource_type:'incident', resource_id:'18', username:'admin', user_role:'superadmin', description:'Incident #18 status: NEW → TRIAGED', reason:'First analysis done, assigning to L2', ip_address:'192.168.1.10', created_at: new Date(Date.now()-1000*60*5).toISOString() },
  { id:2, action:'ALERT_ACK', resource_type:'alert', resource_id:'342', username:'analyst.l2', user_role:'analyst_l2', description:'Alert #342 acknowledged by analyst.l2', reason:'Confirmed brute force, correlated with INC-18', ip_address:'192.168.1.12', created_at: new Date(Date.now()-1000*60*12).toISOString() },
  { id:3, action:'PLAYBOOK_EXECUTE', resource_type:'playbook', resource_id:'isolate_host', username:'admin', user_role:'superadmin', description:"Playbook 'Isolate Host' executed on 'WKSTN-105'", ip_address:'192.168.1.10', created_at: new Date(Date.now()-1000*60*18).toISOString() },
  { id:4, action:'IOC_CREATE', resource_type:'ioc', resource_id:'45.33.22.11', username:'analyst.l2', user_role:'analyst_l2', description:'IoC created: ip:45.33.22.11 (score=87)', ip_address:'192.168.1.12', created_at: new Date(Date.now()-1000*60*32).toISOString() },
  { id:5, action:'LOGIN', resource_type:'session', resource_id:null, username:'admin', user_role:'superadmin', description:"User 'admin' logged in", ip_address:'192.168.1.10', created_at: new Date(Date.now()-1000*60*60).toISOString() },
  { id:6, action:'ALERT_FP', resource_type:'alert', resource_id:'298', username:'analyst.l3', user_role:'analyst_l3', description:'Alert #298 marked as false positive', reason:'Scheduled script, whitelisted in CMDB', ip_address:'192.168.1.15', created_at: new Date(Date.now()-1000*60*90).toISOString() },
];

export default function AuditPage() {
  const [logs, setLogs] = useState(MOCK_LOGS);
  const [filter, setFilter] = useState({ action:'', username:'', resource_type:'' });

  useEffect(() => {
    auditService.list({ limit:200 }).then(r => setLogs(r.data)).catch(() => {});
  }, []);

  const filtered = logs.filter(l =>
    (!filter.action || l.action.includes(filter.action.toUpperCase())) &&
    (!filter.username || l.username.includes(filter.username)) &&
    (!filter.resource_type || l.resource_type === filter.resource_type)
  );

  return (
    <div style={{ padding:24, display:'flex', flexDirection:'column', gap:16, fontFamily:'Inter, sans-serif', color:T.tx1 }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@700&family=JetBrains+Mono:wght@400;500&display=swap');`}</style>

      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end' }}>
        <div>
          <h1 style={{ margin:0, fontFamily:'Space Grotesk', fontSize:26, fontWeight:700, letterSpacing:'-0.02em' }}>Audit Log</h1>
          <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:11, marginTop:4 }}>ISO 27001 A.12.4.1 — Immutable analyst action trail</div>
        </div>
        <button style={{ display:'flex', alignItems:'center', gap:6, background:'transparent', border:`1px solid ${T.bd2}`, color:T.tx1, padding:'7px 12px', borderRadius:4, cursor:'pointer', fontSize:12 }}>
          <Download size={13}/>Export CSV
        </button>
      </div>

      {/* Filters */}
      <div style={{ display:'flex', gap:8 }}>
        {[
          { key:'action', placeholder:'Filter action...', w:160 },
          { key:'username', placeholder:'Filter user...', w:140 },
        ].map(f => (
          <input key={f.key} value={filter[f.key]} onChange={e=>setFilter(p=>({...p,[f.key]:e.target.value}))} placeholder={f.placeholder}
            style={{ width:f.w, background:T.bg1, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'7px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none' }}/>
        ))}
        <select value={filter.resource_type} onChange={e=>setFilter(p=>({...p,resource_type:e.target.value}))} style={{ background:T.bg1, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'7px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none' }}>
          <option value="">All resources</option>
          {['incident','alert','ioc','playbook','rule','session','user'].map(r=><option key={r} value={r}>{r}</option>)}
        </select>
      </div>

      {/* ISO Badge */}
      <div style={{ display:'flex', gap:8 }}>
        {['ISO 27001 A.12.4.1','SOC 2 Type II','GDPR Art.30'].map(b=>(
          <span key={b} style={{ background:`${T.low}1a`, color:T.low, border:`1px solid ${T.low}40`, fontSize:10, padding:'3px 8px', borderRadius:3, fontFamily:'Space Grotesk', fontWeight:700, letterSpacing:'0.04em' }}>✓ {b}</span>
        ))}
      </div>

      {/* Log entries */}
      <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:8, overflow:'hidden' }}>
        <div style={{ display:'grid', gridTemplateColumns:'160px 140px 80px 100px 1fr 120px', gap:12, padding:'10px 16px', background:T.bg2, fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.06em', borderBottom:`1px solid ${T.bd1}` }}>
          <div>TIMESTAMP</div><div>ACTION</div><div>RESOURCE</div><div>USER</div><div>DESCRIPTION</div><div>IP</div>
        </div>
        {filtered.map((log, i) => {
          const ac = ACTION_COLORS[log.action] || T.tx2;
          return (
            <div key={log.id} style={{ display:'grid', gridTemplateColumns:'160px 140px 80px 100px 1fr 120px', gap:12, padding:'11px 16px', borderBottom:`1px solid ${T.bd1}`, fontSize:12, alignItems:'flex-start', background: i%2===0?'transparent':T.bg0 }}>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{new Date(log.created_at).toISOString().replace('T',' ').slice(0,19)}</span>
              <span style={{ fontFamily:'Space Grotesk', color:ac, fontSize:10, fontWeight:700, letterSpacing:'0.04em', borderLeft:`2px solid ${ac}`, paddingLeft:6 }}>{log.action}</span>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{log.resource_type}</span>
              <div>
                <div style={{ color:T.tx1, fontSize:12, fontWeight:500 }}>{log.username}</div>
                <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:9, letterSpacing:'0.04em' }}>{log.user_role}</div>
              </div>
              <div>
                <div style={{ color:T.tx1 }}>{log.description}</div>
                {log.reason && <div style={{ color:T.tx3, fontSize:11, marginTop:3, fontStyle:'italic' }}>"{log.reason}"</div>}
              </div>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{log.ip_address||'—'}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
