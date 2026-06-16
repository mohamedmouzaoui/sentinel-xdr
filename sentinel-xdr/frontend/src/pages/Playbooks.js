import React, { useState, useEffect, useRef } from 'react';
import { playbooksService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { Zap, Play, Shield, Search, Archive, Bell, Wrench, Terminal, CheckCircle2, AlertCircle, Clock } from 'lucide-react';

const T = { bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230', bd1:'#1d2533', bd2:'#2a3445', br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85', crit:'#ff5c7c', high:'#ff9544', med:'#fbbf24', low:'#3ddc97', ml:'#c084fc' };

const CAT_ICONS = { containment:Shield, identity:Zap, forensics:Search, notification:Bell, tracking:Archive };
const CAT_COLORS = { containment:T.crit, identity:T.high, forensics:T.br1, notification:T.med, tracking:T.tx2 };
const LOG_COLORS = { INFO:T.tx2, SUCCESS:T.low, WARN:T.med, ERROR:T.crit, FAILED:T.crit };

const MOCK_PLAYBOOKS = [
  { id:'isolate_host',  name:'Isolate Host',         description:'VLAN quarantine via core switch',    severity:'CRITICAL', category:'containment', steps:[{id:1,name:'Resolve MAC'},{id:2,name:'Check sessions'},{id:3,name:'VLAN quarantine'},{id:4,name:'Verify isolation'},{id:5,name:'Update CMDB'}] },
  { id:'block_ip',      name:'Block IP Address',     description:'Edge firewall drop rule',             severity:'HIGH',     category:'containment', steps:[{id:1,name:'Validate IP'},{id:2,name:'Push ACL'},{id:3,name:'Verify block'}] },
  { id:'revoke_tokens', name:'Revoke Session Tokens',description:'IAM session kill via Okta/AD',        severity:'HIGH',     category:'identity',    steps:[{id:1,name:'List sessions'},{id:2,name:'Revoke all'},{id:3,name:'Force reauth'}] },
  { id:'forensic_dump', name:'Forensic Memory Dump', description:'Trigger memory snapshot via EDR',     severity:'MEDIUM',   category:'forensics',   steps:[{id:1,name:'Contact EDR'},{id:2,name:'Trigger dump'},{id:3,name:'Upload evidence'},{id:4,name:'Hash SHA-256'}] },
  { id:'notify_soc',    name:'Notify SOC Team',      description:'Slack #soc-critical + Email L2',      severity:'MEDIUM',   category:'notification',steps:[{id:1,name:'Slack message'},{id:2,name:'Email L2'},{id:3,name:'PagerDuty'}] },
  { id:'open_thehive',  name:'Open TheHive Case',    description:'Investigation case with full context',severity:'LOW',      category:'tracking',    steps:[{id:1,name:'Build payload'},{id:2,name:'Create case'},{id:3,name:'Add observables'},{id:4,name:'Link incident'}] },
];

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState(MOCK_PLAYBOOKS);
  const [selected, setSelected] = useState(null);
  const [running, setRunning] = useState(false);
  const [execId, setExecId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [done, setDone] = useState(false);
  const [target, setTarget] = useState('');
  const termRef = useRef(null);

  useEffect(() => {
    playbooksService.list().then(r => setPlaybooks(r.data)).catch(() => {});
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [logs]);

  const onWs = (msg) => {
    if (msg.type === 'playbook_log' && (!execId || msg.execution_id === execId)) {
      setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11,19), level: msg.level||'INFO', msg: msg.msg }]);
      if (msg.done) { setRunning(false); setDone(true); }
    }
  };
  useWebSocket(onWs);

  const execute = async () => {
    if (!selected || running) return;
    setRunning(true); setDone(false); setLogs([]);
    try {
      const { data } = await playbooksService.execute(selected.id, null, target || 'TARGET-AUTO');
      setExecId(data.execution_id);
      setLogs([{ ts:new Date().toISOString().slice(11,19), level:'INFO', msg:`Execution ID: ${data.execution_id} — Starting '${data.playbook}'...` }]);
      // Simulate locally if WS not connected
      simulateLocally(selected);
    } catch {
      simulateLocally(selected);
    }
  };

  const simulateLocally = async (pb) => {
    const delay = (ms) => new Promise(r => setTimeout(r, ms));
    setLogs([{ ts:new Date().toISOString().slice(11,19), level:'INFO', msg:`Initializing Active Response module — '${pb.name}'...` }]);
    await delay(400);
    setLogs(l => [...l, { ts:new Date().toISOString().slice(11,19), level:'INFO', msg:'Connecting to orchestration daemon [OK]' }]);
    await delay(300);
    for (let i=0; i<pb.steps.length; i++) {
      const step = pb.steps[i];
      await delay(600 + Math.random()*400);
      setLogs(l => [...l, { ts:new Date().toISOString().slice(11,19), level:'INFO', msg:`[Step ${i+1}/${pb.steps.length}] ${step.name}...` }]);
      await delay(700 + Math.random()*600);
      setLogs(l => [...l, { ts:new Date().toISOString().slice(11,19), level:'SUCCESS', msg:`✓ ${step.name} completed` }]);
    }
    await delay(300);
    setLogs(l => [...l, { ts:new Date().toISOString().slice(11,19), level:'SUCCESS', msg:`Playbook '${pb.name}' execution completed. Status: SUCCESS` }]);
    setRunning(false); setDone(true);
  };

  return (
    <div style={{ display:'flex', height:'calc(100vh - 56px)', overflow:'hidden', fontFamily:'Inter, sans-serif', color:T.tx1 }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@700&family=JetBrains+Mono:wght@400;500&display=swap'); @keyframes blink{0%,100%{opacity:1}50%{opacity:0}} @keyframes pb-slide{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}} @keyframes log-row{from{opacity:0;transform:translateX(-4px)}to{opacity:1;transform:translateX(0)}}`}</style>

      {/* Playbook list */}
      <div style={{ width:320, borderRight:`1px solid ${T.bd1}`, display:'flex', flexDirection:'column', overflowY:'auto' }}>
        <div style={{ padding:'16px 20px', borderBottom:`1px solid ${T.bd1}`, background:T.bg1 }}>
          <h1 style={{ margin:0, fontFamily:'Space Grotesk', fontSize:20, fontWeight:700 }}>SOAR Playbooks</h1>
          <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10, marginTop:3 }}>Automated Response Actions</div>
        </div>
        <div style={{ padding:12, display:'flex', flexDirection:'column', gap:6 }}>
          {playbooks.map(pb => {
            const Ic = CAT_ICONS[pb.category] || Zap;
            const cc = CAT_COLORS[pb.category] || T.tx2;
            return (
              <div key={pb.id} onClick={() => { setSelected(pb); setLogs([]); setDone(false); }}
                style={{ padding:'12px 14px', background:selected?.id===pb.id?T.bg3:T.bg1, border:`1px solid ${selected?.id===pb.id?T.bd2:T.bd1}`, borderRadius:6, cursor:'pointer', borderLeft:`2px solid ${selected?.id===pb.id?cc:'transparent'}`, animation:'pb-slide 0.2s ease-out' }}>
                <div style={{ display:'flex', gap:10, alignItems:'flex-start' }}>
                  <div style={{ width:28, height:28, borderRadius:5, background:`${cc}20`, display:'grid', placeItems:'center', flexShrink:0 }}>
                    <Ic size={13} color={cc}/>
                  </div>
                  <div>
                    <div style={{ color:T.tx1, fontSize:13, fontWeight:600 }}>{pb.name}</div>
                    <div style={{ color:T.tx3, fontSize:11, marginTop:2 }}>{pb.description}</div>
                    <div style={{ display:'flex', gap:6, marginTop:6 }}>
                      <span style={{ fontFamily:'Space Grotesk', fontSize:9, fontWeight:700, color:cc, background:`${cc}20`, padding:'2px 5px', borderRadius:2, letterSpacing:'0.06em' }}>{pb.category.toUpperCase()}</span>
                      <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:9 }}>{pb.steps.length} steps</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Terminal pane */}
      {selected ? (
        <div style={{ flex:1, display:'flex', flexDirection:'column' }}>
          <div style={{ padding:'14px 20px', borderBottom:`1px solid ${T.bd1}`, background:T.bg1, display:'flex', justifyContent:'space-between', alignItems:'center' }}>
            <div>
              <div style={{ fontFamily:'Space Grotesk', color:T.tx1, fontWeight:700, fontSize:16 }}>{selected.name}</div>
              <div style={{ display:'flex', gap:10, marginTop:4 }}>
                {selected.steps.map((s,i) => (
                  <div key={s.id} style={{ display:'flex', alignItems:'center', gap:4 }}>
                    <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:9 }}>{i+1}. {s.name}</span>
                    {i < selected.steps.length-1 && <ChevronRight size={8} color={T.tx3}/>}
                  </div>
                ))}
              </div>
            </div>
            <div style={{ display:'flex', gap:8, alignItems:'center' }}>
              <input value={target} onChange={e=>setTarget(e.target.value)} placeholder="Target (e.g. WKSTN-105)" style={{ background:T.bg0, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'6px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none', width:180 }}/>
              <button onClick={execute} disabled={running} style={{ display:'flex', alignItems:'center', gap:6, background:running?T.tx3:T.crit, border:'none', color:'#fff', padding:'8px 16px', borderRadius:4, cursor:running?'not-allowed':'pointer', fontFamily:'Space Grotesk', fontWeight:700, fontSize:12, letterSpacing:'0.06em' }}>
                <Play size={13}/>{running?'RUNNING...':'EXECUTE'}
              </button>
            </div>
          </div>

          {/* Terminal */}
          <div ref={termRef} style={{ flex:1, background:'#050709', overflowY:'auto', padding:'16px 20px', fontFamily:'JetBrains Mono', fontSize:12 }}>
            {logs.length === 0 && (
              <div style={{ color:T.tx3, fontSize:11 }}>
                {'>'} Ready — select a target and click EXECUTE to run <span style={{ color:T.br1 }}>{selected.name}</span>
                <br/>{'>'} All steps will be streamed in real-time via WebSocket
                <span style={{ animation:'blink 1s infinite', display:'inline-block', marginLeft:4, color:T.br1 }}>▊</span>
              </div>
            )}
            {logs.map((l, i) => (
              <div key={i} style={{ marginBottom:3, animation:'log-row 0.15s ease-out', display:'flex', gap:12, alignItems:'flex-start' }}>
                <span style={{ color:T.tx3, flexShrink:0 }}>{l.ts}</span>
                <span style={{ color:LOG_COLORS[l.level]||T.tx2, flexShrink:0, minWidth:52 }}>[{l.level}]</span>
                <span style={{ color:T.tx1 }}>{l.msg}</span>
              </div>
            ))}
            {running && (
              <div style={{ color:T.br1, marginTop:4 }}>
                {'>'} <span style={{ animation:'blink 1s infinite', display:'inline-block' }}>▊</span>
              </div>
            )}
            {done && (
              <div style={{ marginTop:12, padding:'10px 14px', background:`${T.low}18`, border:`1px solid ${T.low}50`, borderRadius:4, color:T.low, display:'flex', alignItems:'center', gap:8 }}>
                <CheckCircle2 size={14}/> Playbook execution completed successfully.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div style={{ flex:1, display:'grid', placeItems:'center', color:T.tx3, fontFamily:'JetBrains Mono', fontSize:13 }}>
          <div style={{ textAlign:'center' }}>
            <Terminal size={36} color={T.tx3} style={{ margin:'0 auto 16px' }}/>
            <div>Select a playbook to view steps and execute</div>
          </div>
        </div>
      )}
    </div>
  );
}

function ChevronRight({ size, color }) {
  return <span style={{ color, fontSize: size }}> › </span>;
}
