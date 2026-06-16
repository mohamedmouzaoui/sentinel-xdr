import React, { useState, useEffect } from 'react';
import { iocsService } from '../services/api';
import { Network, Plus, Upload, Trash2, Edit3, Shield, Hash, Globe, Mail, FileText, AlertCircle, CheckCircle2 } from 'lucide-react';

const T = { bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230', bd1:'#1d2533', bd2:'#2a3445', br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85', crit:'#ff5c7c', critBg:'#ff5c7c1a', high:'#ff9544', med:'#fbbf24', low:'#3ddc97', ml:'#c084fc' };

const TLP_COLORS = { WHITE:'#e5edf5', GREEN:'#3ddc97', AMBER:'#fbbf24', RED:'#ff5c7c' };
const TYPE_ICONS = { ip: Globe, domain: Globe, url: Globe, hash_md5: Hash, hash_sha1: Hash, hash_sha256: Hash, email: Mail, cve: Shield };

function scoreColor(s) {
  if (s >= 80) return T.crit;
  if (s >= 60) return T.high;
  if (s >= 40) return T.med;
  return T.low;
}

function Card({ children, style }) {
  return <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:8, ...style }}>{children}</div>;
}
function Label({ children, style }) {
  return <div style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.08em', textTransform:'uppercase', ...style }}>{children}</div>;
}

const MOCK_IOCS = [
  { id:1, ioc_type:'ip',         value:'45.33.22.11',  score:87, confidence:0.95, source:'abuseipdb', tlp:'AMBER', tags:['bruteforce','rdp'], hit_count:142, is_active:true, last_seen:'2024-10-27T14:45:00Z' },
  { id:2, ioc_type:'hash_sha256',value:'4d1740...',    score:96, confidence:0.99, source:'virustotal', tlp:'RED',   tags:['ransomware','ryuk'], hit_count:3,   is_active:true, last_seen:'2024-10-27T10:00:00Z' },
  { id:3, ioc_type:'domain',     value:'evil-c2.net',  score:78, confidence:0.88, source:'otx',       tlp:'AMBER', tags:['c2','apt28'],       hit_count:7,   is_active:true, last_seen:'2024-10-26T18:30:00Z' },
  { id:4, ioc_type:'ip',         value:'10.0.5.99',    score:45, confidence:0.6,  source:'internal',  tlp:'WHITE', tags:['suspicious'],       hit_count:23,  is_active:true, last_seen:'2024-10-27T09:12:00Z' },
  { id:5, ioc_type:'url',        value:'http://mal.ru/drop', score:92, confidence:0.97, source:'virustotal', tlp:'RED', tags:['malware','dropper'], hit_count:1, is_active:true, last_seen:'2024-10-25T20:00:00Z' },
];

export default function IoCsPage() {
  const [iocs, setIocs] = useState(MOCK_IOCS);
  const [stats, setStats] = useState({ total:5, critical:3, by_type:{ip:2, domain:1, url:1, hash_sha256:1} });
  const [showAdd, setShowAdd] = useState(false);
  const [filter, setFilter] = useState('');
  const [form, setForm] = useState({ ioc_type:'ip', value:'', score:50, confidence:0.7, source:'manual', tlp:'WHITE', tags:'', description:'' });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    iocsService.list().then(r => setIocs(r.data)).catch(() => {});
    iocsService.stats().then(r => setStats(r.data)).catch(() => {});
  }, []);

  const filtered = iocs.filter(i => !filter || i.value.toLowerCase().includes(filter.toLowerCase()) || i.ioc_type.includes(filter) || i.tags?.some(t => t.includes(filter)));

  const handleAdd = async (e) => {
    e.preventDefault(); setSaving(true);
    try {
      const payload = { ...form, tags: form.tags ? form.tags.split(',').map(t=>t.trim()) : [] };
      const { data } = await iocsService.create(payload);
      setIocs(prev => [data, ...prev]);
      setShowAdd(false);
      setForm({ ioc_type:'ip', value:'', score:50, confidence:0.7, source:'manual', tlp:'WHITE', tags:'', description:'' });
    } catch {
      setIocs(prev => [{ id: Date.now(), ...form, tags: form.tags?form.tags.split(',').map(t=>t.trim()):[], hit_count:0, is_active:true }, ...prev]);
      setShowAdd(false);
    } finally { setSaving(false); }
  };

  const deactivate = async (id) => {
    try { await iocsService.remove(id); } catch {}
    setIocs(prev => prev.map(i => i.id===id ? {...i, is_active:false} : i));
  };

  return (
    <div style={{ padding:24, display:'flex', flexDirection:'column', gap:16, fontFamily:'Inter, sans-serif', color:T.tx1 }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@700&family=JetBrains+Mono:wght@400;500&display=swap'); input,select,textarea{color-scheme:dark;}`}</style>

      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end' }}>
        <div>
          <h1 style={{ margin:0, fontFamily:'Space Grotesk', fontSize:26, fontWeight:700, letterSpacing:'-0.02em' }}>CTI / IoC Management</h1>
          <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:11, marginTop:4 }}>Threat Intelligence · STIX 2.1 / MISP compatible</div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <button style={btnStyle()} onClick={() => {}}><Upload size={13}/>Import MISP/STIX</button>
          <button style={btnStyle(true)} onClick={() => setShowAdd(true)}><Plus size={13}/>Add IoC</button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:12 }}>
        {[
          { label:'Total Active', value:stats.total||0, color:T.br1 },
          { label:'Critical (≥80)', value:stats.critical||0, color:T.crit },
          { label:'IP Addresses', value:stats.by_type?.ip||0, color:T.high },
          { label:'Hashes', value:(stats.by_type?.hash_md5||0)+(stats.by_type?.hash_sha1||0)+(stats.by_type?.hash_sha256||0), color:T.ml },
          { label:'Domains/URLs', value:(stats.by_type?.domain||0)+(stats.by_type?.url||0), color:T.med },
        ].map(s => (
          <Card key={s.label} style={{ padding:'14px 16px' }}>
            <Label style={{ marginBottom:6 }}>{s.label}</Label>
            <div style={{ fontFamily:'Space Grotesk', color:s.color, fontSize:24, fontWeight:700 }}>{s.value}</div>
          </Card>
        ))}
      </div>

      {/* Filter */}
      <div style={{ display:'flex', gap:8, alignItems:'center' }}>
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter by value, type, tag..." style={{ flex:1, maxWidth:360, background:T.bg1, border:`1px solid ${T.bd1}`, color:T.tx1, padding:'8px 12px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none' }}/>
        {['ip','domain','hash_sha256','url','cve'].map(t => (
          <button key={t} onClick={()=>setFilter(filter===t?'':t)} style={{ ...btnStyle(filter===t), padding:'6px 10px', fontSize:10, fontFamily:'Space Grotesk', letterSpacing:'0.06em' }}>{t.toUpperCase()}</button>
        ))}
      </div>

      {/* Table */}
      <Card>
        <div style={{ display:'grid', gridTemplateColumns:'60px 100px 1fr 80px 80px 80px 120px 100px 80px', gap:12, padding:'10px 16px', background:T.bg2, borderBottom:`1px solid ${T.bd1}`, fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.06em' }}>
          <div>TYPE</div><div>TLP</div><div>INDICATOR</div><div>SCORE</div><div>CONF.</div><div>HITS</div><div>SOURCE</div><div>TAGS</div><div>ACTIONS</div>
        </div>
        {filtered.map(ioc => {
          const Ic = TYPE_ICONS[ioc.ioc_type] || Network;
          const sc = scoreColor(ioc.score);
          return (
            <div key={ioc.id} style={{ display:'grid', gridTemplateColumns:'60px 100px 1fr 80px 80px 80px 120px 100px 80px', gap:12, padding:'12px 16px', borderBottom:`1px solid ${T.bd1}`, alignItems:'center', opacity:ioc.is_active?1:0.4 }}>
              <div style={{ display:'flex', alignItems:'center', gap:4 }}>
                <Ic size={12} color={T.tx3}/>
                <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{ioc.ioc_type.replace('hash_','')}</span>
              </div>
              <span style={{ fontFamily:'JetBrains Mono', color:TLP_COLORS[ioc.tlp]||T.tx2, fontSize:10, fontWeight:700, letterSpacing:'0.08em' }}>TLP:{ioc.tlp}</span>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx1, fontSize:12, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{ioc.value}</span>
              <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                <div style={{ width:32, height:3, background:T.bd2, borderRadius:2, overflow:'hidden' }}>
                  <div style={{ width:`${ioc.score}%`, height:'100%', background:sc }}/>
                </div>
                <span style={{ fontFamily:'JetBrains Mono', color:sc, fontSize:11, fontWeight:700 }}>{ioc.score}</span>
              </div>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx2, fontSize:11 }}>{Math.round((ioc.confidence||0)*100)}%</span>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx2, fontSize:11 }}>{ioc.hit_count||0}</span>
              <span style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10 }}>{ioc.source}</span>
              <div style={{ display:'flex', gap:3, flexWrap:'wrap' }}>
                {(ioc.tags||[]).slice(0,2).map(t => (
                  <span key={t} style={{ background:`${T.ml}22`, color:T.ml, fontSize:9, padding:'1px 5px', borderRadius:2, fontFamily:'Space Grotesk', fontWeight:700 }}>{t}</span>
                ))}
              </div>
              <div style={{ display:'flex', gap:6 }}>
                <button title="Edit" style={{ background:'none', border:'none', color:T.tx3, cursor:'pointer', padding:2 }}><Edit3 size={12}/></button>
                <button title="Deactivate" onClick={()=>deactivate(ioc.id)} style={{ background:'none', border:'none', color:T.tx3, cursor:'pointer', padding:2 }}><Trash2 size={12}/></button>
              </div>
            </div>
          );
        })}
      </Card>

      {/* Add IoC Modal */}
      {showAdd && (
        <div style={{ position:'fixed', inset:0, background:'#00000090', display:'grid', placeItems:'center', zIndex:1000 }}>
          <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:10, padding:28, width:480 }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:20 }}>
              <h2 style={{ margin:0, fontFamily:'Space Grotesk', color:T.tx1, fontSize:18 }}>Add Indicator of Compromise</h2>
              <button onClick={()=>setShowAdd(false)} style={{ background:'none', border:'none', color:T.tx3, cursor:'pointer', fontSize:18 }}>×</button>
            </div>
            <form onSubmit={handleAdd} style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
                <Field label="Type">
                  <select value={form.ioc_type} onChange={e=>setForm(f=>({...f,ioc_type:e.target.value}))} style={inputStyle()}>
                    {['ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','cve'].map(t=><option key={t} value={t}>{t}</option>)}
                  </select>
                </Field>
                <Field label="TLP">
                  <select value={form.tlp} onChange={e=>setForm(f=>({...f,tlp:e.target.value}))} style={inputStyle()}>
                    {['WHITE','GREEN','AMBER','RED'].map(t=><option key={t} value={t}>{t}</option>)}
                  </select>
                </Field>
              </div>
              <Field label="Indicator Value">
                <input value={form.value} onChange={e=>setForm(f=>({...f,value:e.target.value}))} placeholder="e.g. 45.33.22.11 or malicious.domain.com" style={inputStyle()} required/>
              </Field>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
                <Field label={`Score (${form.score})`}><input type="range" min="0" max="100" value={form.score} onChange={e=>setForm(f=>({...f,score:+e.target.value}))} style={{ width:'100%', accentColor:scoreColor(form.score) }}/></Field>
                <Field label="Source">
                  <select value={form.source} onChange={e=>setForm(f=>({...f,source:e.target.value}))} style={inputStyle()}>
                    {['manual','misp','otx','abuseipdb','virustotal','internal'].map(s=><option key={s} value={s}>{s}</option>)}
                  </select>
                </Field>
                <Field label="Tags (comma-sep)"><input value={form.tags} onChange={e=>setForm(f=>({...f,tags:e.target.value}))} placeholder="apt28, c2" style={inputStyle()}/></Field>
              </div>
              <Field label="Description"><textarea value={form.description} onChange={e=>setForm(f=>({...f,description:e.target.value}))} rows={2} style={{ ...inputStyle(), resize:'vertical' }}/></Field>
              <div style={{ display:'flex', gap:8, justifyContent:'flex-end', marginTop:4 }}>
                <button type="button" onClick={()=>setShowAdd(false)} style={btnStyle()}>Cancel</button>
                <button type="submit" disabled={saving} style={btnStyle(true)}>{saving?'Saving...':'Add IoC'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <div style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:'#5d6d85', letterSpacing:'0.06em', marginBottom:5 }}>{label.toUpperCase()}</div>
      {children}
    </div>
  );
}

function inputStyle() {
  return { width:'100%', background:'#070a0e', border:'1px solid #1d2533', color:'#e5edf5', padding:'8px 10px', borderRadius:4, fontSize:12, fontFamily:'JetBrains Mono', outline:'none' };
}
function btnStyle(primary) {
  return { display:'inline-flex', alignItems:'center', gap:6, background:primary?'#22d3ee':'transparent', color:primary?'#070a0e':'#e5edf5', border:primary?'none':'1px solid #2a3445', padding:'7px 14px', borderRadius:4, cursor:'pointer', fontSize:12, fontWeight:600 };
}
