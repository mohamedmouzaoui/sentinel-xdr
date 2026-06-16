import React, { useState } from 'react';
import { FileCode, ToggleLeft, ToggleRight, Sparkles, BarChart2 } from 'lucide-react';

const T = { bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230', bd1:'#1d2533', bd2:'#2a3445', br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85', crit:'#ff5c7c', high:'#ff9544', med:'#fbbf24', low:'#3ddc97', ml:'#c084fc' };
const SEV_C = { CRITICAL:T.crit, HIGH:T.high, MEDIUM:T.med, LOW:T.low };

const MOCK_RULES = [
  { rule_id:'XDR-001', name:'SSH Brute Force',               severity:'CRITICAL', mitre_tactic:'Credential Access', mitre_technique:'T1110', hit_count:342, is_active:true,  false_positive_count:3  },
  { rule_id:'XDR-007', name:'AMSI Bypass PowerShell',         severity:'HIGH',     mitre_tactic:'Defense Evasion',   mitre_technique:'T1562', hit_count:28,  is_active:true,  false_positive_count:1  },
  { rule_id:'XDR-012', name:'Pass-the-Hash Lateral Movement', severity:'CRITICAL', mitre_tactic:'Lateral Movement',  mitre_technique:'T1550', hit_count:12,  is_active:true,  false_positive_count:0  },
  { rule_id:'XDR-019', name:'Anomalous DNS C2 Beacon',        severity:'HIGH',     mitre_tactic:'C2',                mitre_technique:'T1071', hit_count:67,  is_active:true,  false_positive_count:8  },
  { rule_id:'XDR-025', name:'Horizontal Port Scan',           severity:'MEDIUM',   mitre_tactic:'Discovery',         mitre_technique:'T1046', hit_count:189, is_active:true,  false_positive_count:24 },
  { rule_id:'XDR-031', name:'Scheduled Task Persistence',     severity:'MEDIUM',   mitre_tactic:'Persistence',       mitre_technique:'T1053', hit_count:15,  is_active:false, false_positive_count:2  },
  { rule_id:'XDR-040', name:'Shadow Copy Deletion',           severity:'CRITICAL', mitre_tactic:'Impact',            mitre_technique:'T1490', hit_count:3,   is_active:true,  false_positive_count:0  },
];

const ML_MODELS = [
  { name:'IsolationForest — Anomaly Detector', status:'active', accuracy:'94.2%', features:['shannon_entropy','src_ip_freq','after_hours','port_diversity','failed_logins','bytes_out','request_rate','mitre_score','host_criticality','time_since_last'], last_trained:'2024-10-27', alerts_7d:89 },
  { name:'RandomForest — Severity Classifier', status:'active', accuracy:'91.7%', features:['score','source_country','sigma_weight','time_to_alert','alert_chain_len'], last_trained:'2024-10-25', alerts_7d:342 },
];

export default function RulesPage() {
  const [rules, setRules] = useState(MOCK_RULES);

  const toggle = (ruleId) => setRules(prev => prev.map(r => r.rule_id===ruleId ? {...r, is_active:!r.is_active} : r));

  return (
    <div style={{ padding:24, fontFamily:'Inter, sans-serif', color:T.tx1, display:'flex', flexDirection:'column', gap:20 }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@700&family=JetBrains+Mono:wght@400;500&display=swap');`}</style>
      <h1 style={{ margin:0, fontFamily:'Space Grotesk', fontSize:26, fontWeight:700, letterSpacing:'-0.02em' }}>Rules & ML Engine</h1>

      {/* Sigma rules */}
      <section>
        <div style={{ fontFamily:'Space Grotesk', color:T.tx3, fontSize:11, fontWeight:700, letterSpacing:'0.08em', marginBottom:12 }}>SIGMA DETECTION RULES</div>
        <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:8, overflow:'hidden' }}>
          <div style={{ display:'grid', gridTemplateColumns:'80px 1fr 90px 120px 100px 80px 60px 80px', gap:12, padding:'9px 16px', background:T.bg2, fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.06em', borderBottom:`1px solid ${T.bd1}` }}>
            <div>ID</div><div>RULE NAME</div><div>SEVERITY</div><div>MITRE TACTIC</div><div>TECHNIQUE</div><div>HITS</div><div>FP</div><div>STATUS</div>
          </div>
          {rules.map(r => (
            <div key={r.rule_id} style={{ display:'grid', gridTemplateColumns:'80px 1fr 90px 120px 100px 80px 60px 80px', gap:12, padding:'11px 16px', borderBottom:`1px solid ${T.bd1}`, alignItems:'center', opacity:r.is_active?1:0.5 }}>
              <span style={{ fontFamily:'JetBrains Mono', color:T.br1, fontSize:11 }}>{r.rule_id}</span>
              <span style={{ color:T.tx1, fontSize:12, fontWeight:500 }}>{r.name}</span>
              <span style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:SEV_C[r.severity], letterSpacing:'0.04em' }}>{r.severity}</span>
              <span style={{ color:T.tx2, fontSize:11 }}>{r.mitre_tactic}</span>
              <span style={{ fontFamily:'JetBrains Mono', color:T.ml, fontSize:11 }}>{r.mitre_technique}</span>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx1, fontSize:12, fontWeight:700 }}>{r.hit_count}</span>
              <span style={{ fontFamily:'JetBrains Mono', color:r.false_positive_count>5?T.high:T.tx3, fontSize:11 }}>{r.false_positive_count}</span>
              <button onClick={()=>toggle(r.rule_id)} style={{ display:'flex', alignItems:'center', gap:4, background:'none', border:'none', cursor:'pointer', color:r.is_active?T.low:T.tx3, fontFamily:'Space Grotesk', fontSize:10, fontWeight:700 }}>
                {r.is_active ? <ToggleRight size={18} color={T.low}/> : <ToggleLeft size={18} color={T.tx3}/>}
                {r.is_active?'ON':'OFF'}
              </button>
            </div>
          ))}
        </div>
      </section>

      {/* ML Models */}
      <section>
        <div style={{ fontFamily:'Space Grotesk', color:T.tx3, fontSize:11, fontWeight:700, letterSpacing:'0.08em', marginBottom:12 }}>MACHINE LEARNING MODELS</div>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
          {ML_MODELS.map(m => (
            <div key={m.name} style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:8, padding:18 }}>
              <div style={{ display:'flex', gap:10, marginBottom:14 }}>
                <div style={{ width:36, height:36, borderRadius:7, background:`${T.ml}20`, display:'grid', placeItems:'center' }}>
                  <Sparkles size={16} color={T.ml}/>
                </div>
                <div>
                  <div style={{ color:T.tx1, fontWeight:600, fontSize:13 }}>{m.name}</div>
                  <div style={{ display:'flex', gap:8, marginTop:3 }}>
                    <span style={{ fontFamily:'JetBrains Mono', color:T.low, fontSize:10 }}>● {m.status.toUpperCase()}</span>
                    <span style={{ fontFamily:'JetBrains Mono', color:T.br1, fontSize:10 }}>Acc: {m.accuracy}</span>
                  </div>
                </div>
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, fontFamily:'JetBrains Mono', fontSize:10, marginBottom:12 }}>
                <div style={{ background:T.bg2, borderRadius:4, padding:'8px 10px' }}>
                  <div style={{ color:T.tx3, marginBottom:3 }}>Last trained</div>
                  <div style={{ color:T.tx1 }}>{m.last_trained}</div>
                </div>
                <div style={{ background:T.bg2, borderRadius:4, padding:'8px 10px' }}>
                  <div style={{ color:T.tx3, marginBottom:3 }}>Alerts (7d)</div>
                  <div style={{ color:T.tx1 }}>{m.alerts_7d}</div>
                </div>
              </div>
              <div>
                <div style={{ fontFamily:'Space Grotesk', color:T.tx3, fontSize:9, fontWeight:700, letterSpacing:'0.08em', marginBottom:6 }}>FEATURES ({m.features.length})</div>
                <div style={{ display:'flex', gap:3, flexWrap:'wrap' }}>
                  {m.features.map(f => (
                    <span key={f} style={{ fontFamily:'JetBrains Mono', color:T.br1, background:`${T.br1}15`, fontSize:9, padding:'2px 5px', borderRadius:2 }}>{f}</span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
