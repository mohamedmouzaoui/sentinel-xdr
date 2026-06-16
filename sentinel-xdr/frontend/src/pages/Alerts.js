import React, { useState, useEffect, useCallback } from 'react';
import { alertsService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { ShieldAlert, CheckCircle2, XCircle, Eye, Filter, RefreshCw, Zap, Globe, Hash, Clock } from 'lucide-react';

const T = { bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230', bd1:'#1d2533', bd2:'#2a3445', br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85', crit:'#ff5c7c', critBg:'#ff5c7c18', high:'#ff9544', highBg:'#ff95441a', med:'#fbbf24', medBg:'#fbbf241a', low:'#3ddc97', lowBg:'#3ddc971a' };

const SEV = { CRITICAL:{c:T.crit,bg:T.critBg}, HIGH:{c:T.high,bg:T.highBg}, MEDIUM:{c:T.med,bg:T.medBg}, LOW:{c:T.low,bg:T.lowBg} };

const MOCK = [
  { id:1, timestamp:'2024-10-27T14:45:00Z', title:'Brute Force SSH — 342 attempts in 5 min', severity:'CRITICAL', score:94, source_ip:'45.33.22.11', target_hostname:'dc01', mitre_tactic:'Credential Access', mitre_technique:'T1110', sigma_rule_id:'XDR-001', is_processed:false, is_false_positive:false, incident_id:18 },
  { id:2, timestamp:'2024-10-27T14:31:00Z', title:'Suspicious PowerShell — AMSI Bypass Detected', severity:'HIGH', score:81, source_ip:'10.0.5.99', target_hostname:'WKSTN-105', mitre_tactic:'Defense Evasion', mitre_technique:'T1562', sigma_rule_id:'XDR-007', is_processed:false, is_false_positive:false, incident_id:null },
  { id:3, timestamp:'2024-10-27T14:18:00Z', title:'Lateral Movement — SMB Lateral Move via Pass-the-Hash', severity:'CRITICAL', score:97, source_ip:'10.0.5.99', target_hostname:'db01', mitre_tactic:'Lateral Movement', mitre_technique:'T1550', sigma_rule_id:'XDR-012', is_processed:false, is_false_positive:false, incident_id:18 },
  { id:4, timestamp:'2024-10-27T13:55:00Z', title:'Anomalous Outbound DNS — Possible C2 Beacon', severity:'HIGH', score:76, source_ip:'10.0.4.22', target_hostname:'WEB-02', mitre_tactic:'Command and Control', mitre_technique:'T1071', sigma_rule_id:'XDR-019', is_processed:true, is_false_positive:false, incident_id:17 },
  { id:5, timestamp:'2024-10-27T13:30:00Z', title:'Scheduled Task Creation — Persistence Mechanism', severity:'MEDIUM', score:58, source_ip:'10.0.5.99', target_hostname:'WKSTN-105', mitre_tactic:'Persistence', mitre_technique:'T1053', sigma_rule_id:'XDR-004', is_processed:false, is_false_positive:false, incident_id:null },
  { id:6, timestamp:'2024-10-27T13:10:00Z', title:'Port Scan Detected — 6400 ports in 30s', severity:'MEDIUM', score:52, source_ip:'192.168.0.155', target_hostname:'—', mitre_tactic:'Discovery', mitre_technique:'T1046', sigma_rule_id:'XDR-025', is_processed:true, is_false_positive:true, incident_id:null },
];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState(MOCK);
  const [stats, setStats] = useState({ total:342, by_severity:{CRITICAL:45,HIGH:102,MEDIUM:156,LOW:39}, unacknowledged:87 });
  const [selected, setSelected] = useState(null);
  const [filterSev, setFilterSev] = useState('');
  const [filterUnack, setFilterUnack] = useState(false);
  const [ackModal, setAckModal] = useState(null);
  const [ackReason, setAckReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [liveCount, setLiveCount] = useState(0);

  const onWs = useCallback(msg => {
    if (msg.type === 'alert_new') {
      setAlerts(prev => [msg, ...prev]);
      setLiveCount(c => c + 1);
    }
  }, []);
  useWebSocket(onWs);

  useEffect(() => {
    alertsService.list({ limit:100 }).then(r => setAlerts(r.data)).catch(() => {});
    alertsService.stats().then(r => setStats(r.data)).catch(() => {});
  }, []);

  const doAck = async () => {
    if (!ackModal) return;
    setLoading(true);
    try {
      await alertsService.acknowledge(ackModal.id, ackReason);
    } catch {}
    setAlerts(prev => prev.map(a => a.id === ackModal.id ? { ...a, is_processed:true } : a));
    setAckModal(null); setAckReason(''); setLoading(false);
  };

  const markFP = async (alert) => {
    const reason = window.prompt('Reason for false positive:');
    if (reason === null) return;
    try { await alertsService.falsePositive(alert.id, reason || 'No reason given'); } catch {}
    setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, is_false_positive:true, is_processed:true } : a));
  };

  const filtered = alerts.filter(a =>
    (!filterSev || a.severity === filterSev) &&
    (!filterUnack || !a.is_processed)
  );

  return (
    <div style={{ display:'flex', height:'calc(100vh - 56px)', overflow:'hidden', fontFamily:'Inter, sans-serif', color:T.tx1 }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@700&family=JetBrains+Mono:wght@400;500&display=swap'); @keyframes slide-left{from{transform:translateX(20px);opacity:0}to{transform:translateX(0);opacity:1}} @keyframes flash{0%,100%{background:transparent}50%{background:#ff5c7c18}}`}</style>
      {/* Main list */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        {/* Header */}
        <div style={{ padding:'16px 24px', borderBottom:`1px solid ${T.bd1}`, background:T.bg1, flexShrink:0 }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
            <div>
              <h1 style={{ margin:0, fontFamily:'Space Grotesk', fontSize:22, fontWeight:700 }}>Alerts
                {liveCount > 0 && <span style={{ marginLeft:8, fontSize:11, color:T.crit, fontFamily:'JetBrains Mono', background:T.critBg, padding:'2px 8px', borderRadius:10 }}>+{liveCount} live</span>}
              </h1>
            </div>
            <div style={{ display:'flex', gap:8 }}>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
                <button key={s} onClick={() => setFilterSev(filterSev===s?'':s)} style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, padding:'4px 10px', borderRadius:3, border:`1px solid ${SEV[s].c}40`, background:filterSev===s?SEV[s].c:SEV[s].bg, color:filterSev===s?T.bg0:SEV[s].c, cursor:'pointer', letterSpacing:'0.06em' }}>{s} {stats.by_severity?.[s]||0}</button>
              ))}
              <button onClick={() => setFilterUnack(!filterUnack)} style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, padding:'4px 10px', borderRadius:3, border:`1px solid ${T.bd2}`, background:filterUnack?T.br1:'transparent', color:filterUnack?T.bg0:T.tx2, cursor:'pointer' }}>UNACK ONLY</button>
            </div>
          </div>
        </div>

        {/* Table */}
        <div style={{ flex:1, overflowY:'auto' }}>
          <div style={{ display:'grid', gridTemplateColumns:'180px 80px 60px 1fr 120px 110px 100px 80px', gap:12, padding:'8px 20px', background:T.bg2, position:'sticky', top:0, borderBottom:`1px solid ${T.bd1}`, fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.06em', zIndex:5 }}>
            <div>TIME</div><div>SEV</div><div>SCORE</div><div>TITLE</div><div>SOURCE IP</div><div>MITRE</div><div>RULE</div><div>ACTIONS</div>
          </div>
          {filtered.map(a => {
            const sc = SEV[a.severity] || SEV.LOW;
            const isNew = !a.is_processed;
            return (
              <div key={a.id} onClick={() => setSelected(a)}
                style={{ display:'grid', gridTemplateColumns:'180px 80px 60px 1fr 120px 110px 100px 80px', gap:12, padding:'11px 20px', borderBottom:`1px solid ${T.bd1}`, alignItems:'center', cursor:'pointer', background:selected?.id===a.id?T.bg3:'transparent', opacity:a.is_false_positive?0.4:1, borderLeft:`2px solid ${isNew?sc.c:'transparent'}` }}>
                <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{new Date(a.timestamp).toISOString().slice(11,19)} UTC</span>
                <span style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:sc.c, background:sc.bg, padding:'2px 7px', borderRadius:3, textAlign:'center', letterSpacing:'0.04em' }}>{a.severity}</span>
                <span style={{ fontFamily:'JetBrains Mono', color:sc.c, fontSize:12, fontWeight:700 }}>{a.score}</span>
                <div>
                  <div style={{ color:T.tx1, fontSize:12, fontWeight:500 }}>{a.title}</div>
                  {a.incident_id && <span style={{ fontFamily:'JetBrains Mono', color:T.br1, fontSize:9, marginTop:2, display:'block' }}>↳ INC-{a.incident_id}</span>}
                </div>
                <span style={{ fontFamily:'JetBrains Mono', color:T.tx2, fontSize:11 }}>{a.source_ip||'—'}</span>
                <div>
                  <div style={{ fontFamily:'JetBrains Mono', color:T.ml||'#c084fc', fontSize:10 }}>{a.mitre_technique}</div>
                  <div style={{ color:T.tx3, fontSize:10 }}>{a.mitre_tactic}</div>
                </div>
                <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{a.sigma_rule_id||'—'}</span>
                <div style={{ display:'flex', gap:4 }} onClick={e => e.stopPropagation()}>
                  {!a.is_processed && <button title="Acknowledge" onClick={() => setAckModal(a)} style={iconBtn(T.low)}><CheckCircle2 size={13}/></button>}
                  {!a.is_false_positive && !a.is_processed && <button title="False Positive" onClick={() => markFP(a)} style={iconBtn(T.med)}><XCircle size={13}/></button>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail sidebar */}
      {selected && (
        <div style={{ width:360, background:T.bg1, borderLeft:`1px solid ${T.bd1}`, overflowY:'auto', animation:'slide-left 0.2s ease-out', flexShrink:0 }}>
          <div style={{ padding:18, borderBottom:`1px solid ${T.bd1}`, display:'flex', justifyContent:'space-between', alignItems:'center' }}>
            <span style={{ fontFamily:'Space Grotesk', color:T.tx1, fontWeight:700 }}>Alert Detail</span>
            <button onClick={()=>setSelected(null)} style={{ background:'none', border:'none', color:T.tx3, cursor:'pointer', fontSize:18 }}>×</button>
          </div>
          <div style={{ padding:18, display:'flex', flexDirection:'column', gap:14 }}>
            <div>
              <div style={{ fontFamily:'JetBrains Mono', color:SEV[selected.severity]?.c, fontSize:11, fontWeight:700, marginBottom:6 }}>{selected.severity} · {selected.score}/100</div>
              <div style={{ color:T.tx1, fontSize:14, fontWeight:600, lineHeight:1.4 }}>{selected.title}</div>
            </div>
            <div style={{ background:T.bg2, borderRadius:6, padding:12, display:'flex', flexDirection:'column', gap:8, fontFamily:'JetBrains Mono', fontSize:11 }}>
              {[
                ['Time', new Date(selected.timestamp).toISOString().replace('T',' ').slice(0,19)],
                ['Source IP', selected.source_ip||'—'],
                ['Target', selected.target_hostname||'—'],
                ['MITRE Tactic', selected.mitre_tactic||'—'],
                ['Technique', selected.mitre_technique||'—'],
                ['Sigma Rule', selected.sigma_rule_id||'—'],
                ['Incident', selected.incident_id?`INC-${selected.incident_id}`:'Not correlated'],
                ['Status', selected.is_false_positive?'False Positive':selected.is_processed?'Acknowledged':'New'],
              ].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', gap:8 }}>
                  <span style={{ color:T.tx3 }}>{k}</span>
                  <span style={{ color:T.tx1, textAlign:'right', maxWidth:180, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{v}</span>
                </div>
              ))}
            </div>
            {!selected.is_processed && (
              <button onClick={() => setAckModal(selected)} style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:6, background:T.low, border:'none', color:T.bg0, padding:'9px', borderRadius:5, cursor:'pointer', fontFamily:'Space Grotesk', fontWeight:700, fontSize:12, letterSpacing:'0.06em' }}>
                <CheckCircle2 size={14}/>ACKNOWLEDGE
              </button>
            )}
          </div>
        </div>
      )}

      {/* Acknowledge Modal */}
      {ackModal && (
        <div style={{ position:'fixed', inset:0, background:'#00000090', display:'grid', placeItems:'center', zIndex:1000 }}>
          <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:10, padding:24, width:420 }}>
            <h3 style={{ margin:'0 0 8px', fontFamily:'Space Grotesk', color:T.tx1 }}>Acknowledge Alert #{ackModal.id}</h3>
            <p style={{ color:T.tx2, fontSize:13, margin:'0 0 16px' }}>{ackModal.title}</p>
            <label style={{ display:'block', marginBottom:12 }}>
              <div style={{ color:T.tx3, fontSize:11, fontFamily:'Space Grotesk', fontWeight:700, letterSpacing:'0.06em', marginBottom:6 }}>REASON / ANALYST NOTE</div>
              <textarea value={ackReason} onChange={e=>setAckReason(e.target.value)} rows={3} placeholder="e.g. Confirmed attack, correlated to INC-18, blocking IP..." style={{ width:'100%', background:T.bg0, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'8px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none', resize:'vertical' }}/>
            </label>
            <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
              <button onClick={()=>{setAckModal(null);setAckReason('');}} style={{ background:'transparent', border:`1px solid ${T.bd2}`, color:T.tx1, padding:'7px 14px', borderRadius:4, cursor:'pointer', fontSize:12 }}>Cancel</button>
              <button onClick={doAck} disabled={loading} style={{ background:T.low, border:'none', color:T.bg0, padding:'7px 16px', borderRadius:4, cursor:'pointer', fontSize:12, fontWeight:700, fontFamily:'Space Grotesk' }}>{loading?'..':'Acknowledge'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function iconBtn(color) {
  return { background:`${color}20`, border:`1px solid ${color}40`, color, padding:'3px 5px', borderRadius:3, cursor:'pointer', display:'grid', placeItems:'center' };
}
