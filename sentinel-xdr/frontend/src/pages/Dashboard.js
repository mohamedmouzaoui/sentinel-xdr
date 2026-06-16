import React, { useState, useEffect } from 'react';
import { dashboardService, alertsService, incidentsService, reportsService } from '../services/api';
import {
  Activity, Bell, ShieldAlert, Sparkles, TrendingUp, TrendingDown,
  Clock, Target, Download, RefreshCw, Crosshair, Flame
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

const T = {
  bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230',
  bd1:'#1d2533', bd2:'#2a3445',
  br1:'#22d3ee', br3:'#0891b2', brGlow:'#22d3ee20',
  tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85',
  crit:'#ff5c7c', critBg:'#ff5c7c1a',
  high:'#ff9544', highBg:'#ff95441a',
  med:'#fbbf24', medBg:'#fbbf241a',
  low:'#3ddc97', lowBg:'#3ddc971a',
  ml:'#c084fc', mlBg:'#c084fc1a',
};

const KILL_CHAIN = [
  { tactic:'Initial Access',    covered:8 },
  { tactic:'Execution',         covered:12 },
  { tactic:'Persistence',       covered:6 },
  { tactic:'Priv. Escalation',  covered:9 },
  { tactic:'Defense Evasion',   covered:7 },
  { tactic:'Cred. Access',      covered:11 },
  { tactic:'Discovery',         covered:5 },
  { tactic:'Lateral Movement',  covered:6 },
  { tactic:'Collection',        covered:4 },
  { tactic:'Exfiltration',      covered:5 },
  { tactic:'Impact',            covered:3 },
];

const MOCK_TIMESERIES = Array.from({length:24}, (_,i) => {
  const base = (i >= 9 && i <= 18) ? 800000 : 250000;
  return { hour: `${String(i).padStart(2,'0')}:00`, events: Math.round(base + Math.random()*200000), alerts: Math.round(Math.random()*120+20), anomalies: Math.round(Math.random()*12) };
});

const SEV_COLORS = { CRITICAL: T.crit, HIGH: T.high, MEDIUM: T.med, LOW: T.low };

function Card({ children, style, glow }) {
  return <div style={{ background: T.bg1, border:`1px solid ${T.bd1}`, borderRadius:8, boxShadow: glow?`0 0 24px -8px ${T.brGlow}`:'none', ...style }}>{children}</div>;
}
function Label({ children, style }) {
  return <div style={{ fontFamily:'Space Grotesk', fontSize:10, fontWeight:700, color:T.tx3, letterSpacing:'0.08em', textTransform:'uppercase', ...style }}>{children}</div>;
}

export default function DashboardPage() {
  const [overview, setOverview] = useState(null);
  const [alertStats, setAlertStats] = useState(null);
  const [incStats, setIncStats] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const [ov, as, is] = await Promise.all([
        dashboardService.overview(),
        alertsService.stats(),
        incidentsService.stats(),
      ]);
      setOverview(ov.data);
      setAlertStats(as.data);
      setIncStats(is.data);
    } catch {
      // Use mock data if backend not connected
      setOverview({ kpis: { total_events_24h:14293881, active_alerts:342, open_incidents:18, ml_anomalies:89, avg_mttd_minutes:8.4, avg_mttr_minutes:47.2, sla_breached:3 }, severity_distribution:{CRITICAL:45,HIGH:102,MEDIUM:156,LOW:39} });
      setAlertStats({ total:342, by_severity:{CRITICAL:45,HIGH:102,MEDIUM:156,LOW:39}, unacknowledged:87, false_positives:12 });
      setIncStats({ total:18, open:11, sla_breached:3, avg_mttr_minutes:47.2 });
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); const id = setInterval(load, 30000); return ()=>clearInterval(id); }, []);

  const kpis = overview?.kpis || {};
  const sevDist = overview?.severity_distribution || {};
  const pieData = Object.entries(SEV_COLORS).map(([k, c]) => ({ name:k, value:sevDist[k]||0, color:c }));

  const downloadWeekly = async () => {
    try {
      const { data } = await reportsService.weeklyPdf();
      const url = URL.createObjectURL(new Blob([data], {type:'application/pdf'}));
      const a = document.createElement('a'); a.href=url; a.download='soc_weekly_report.pdf'; a.click();
      URL.revokeObjectURL(url);
    } catch { alert('Backend not connected'); }
  };

  return (
    <div style={{ padding:24, display:'flex', flexDirection:'column', gap:16 }}>
      <style>{`@keyframes stagger{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}} .sg>*{animation:stagger 0.4s ease-out both} .sg>*:nth-child(1){animation-delay:0.05s} .sg>*:nth-child(2){animation-delay:0.1s} .sg>*:nth-child(3){animation-delay:0.15s} .sg>*:nth-child(4){animation-delay:0.2s} .sg>*:nth-child(5){animation-delay:0.25s} .sg>*:nth-child(6){animation-delay:0.3s} @keyframes pulse-dot{0%,100%{transform:scale(1)}50%{transform:scale(1.5);opacity:0.5}} .pdot{animation:pulse-dot 2s infinite}`}</style>
      <div className="sg" style={{ display:'contents' }}>

      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end' }}>
        <div>
          <h1 style={{ margin:0, fontFamily:'Space Grotesk', color:T.tx1, fontSize:26, fontWeight:700, letterSpacing:'-0.02em' }}>Command Center</h1>
          <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:11, marginTop:4 }}>
            Global Security Posture · {new Date().toUTCString().slice(0,25)}
          </div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <button onClick={downloadWeekly} style={{ display:'flex', alignItems:'center', gap:6, background:'transparent', border:`1px solid ${T.bd2}`, color:T.tx1, padding:'7px 12px', borderRadius:4, cursor:'pointer', fontSize:12 }}>
            <Download size={13} />Weekly PDF
          </button>
          <button onClick={load} style={{ display:'flex', alignItems:'center', gap:6, background:T.br1, border:'none', color:T.bg0, padding:'7px 14px', borderRadius:4, cursor:'pointer', fontSize:12, fontWeight:700 }}>
            <RefreshCw size={13} />Refresh
          </button>
        </div>
      </div>

      {/* KPIs */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
        <KpiCard label="Total Events 24h"  value={(kpis.total_events_24h||0).toLocaleString()} delta="+12% vs prev 24h" trend="up" icon={Activity} color={T.br1} />
        <KpiCard label="Active Alerts"     value={kpis.active_alerts||0}       delta={`${sevDist.CRITICAL||0} Crit · ${sevDist.HIGH||0} High`} icon={Bell}      color={T.crit} pulse />
        <KpiCard label="Open Incidents"    value={kpis.open_incidents||0}       delta={kpis.sla_breached ? `⚠ ${kpis.sla_breached} SLA breached` : "All within SLA"} icon={ShieldAlert} color={T.high} />
        <KpiCard label="ML Anomalies"      value={kpis.ml_anomalies||0}         delta="Behavioral baseline" icon={Sparkles} color={T.ml} />
      </div>

      {/* SOC Performance Row */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
        <MetricCard label="MTTD" value={kpis.avg_mttd_minutes ? `${kpis.avg_mttd_minutes}m` : '—'} desc="Mean Time to Detect" color={T.br1} icon={Target} />
        <MetricCard label="MTTR" value={kpis.avg_mttr_minutes ? `${kpis.avg_mttr_minutes}m` : '—'} desc="Mean Time to Respond" color={T.low} icon={Clock} />
        <MetricCard label="SLA Breaches"  value={kpis.sla_breached || 0} desc="Active incidents over SLA" color={kpis.sla_breached ? T.crit : T.low} icon={Flame} />
        <MetricCard label="False Positives" value={alertStats?.false_positives || 0} desc="Marked this period" color={T.med} icon={Crosshair} />
      </div>

      {/* Charts Row */}
      <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:12 }}>
        <Card style={{ padding:20 }} glow>
          <div style={{ display:'flex', justifyContent:'space-between', marginBottom:12 }}>
            <div>
              <Label>Event Volume vs Alert Spikes</Label>
              <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10, marginTop:2 }}>last 24h · 1h buckets</div>
            </div>
            <div style={{ display:'flex', gap:12, fontFamily:'JetBrains Mono', fontSize:10, color:T.tx2 }}>
              {[{c:T.br1,l:'EVENTS'},{c:T.crit,l:'ALERTS'},{c:T.ml,l:'ML'}].map(x=>(
                <span key={x.l} style={{ display:'flex', alignItems:'center', gap:4 }}><span style={{ width:8, height:2, background:x.c, display:'inline-block'}}/>{x.l}</span>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={MOCK_TIMESERIES}>
              <defs>
                <linearGradient id="gE" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={T.br1} stopOpacity={0.4}/><stop offset="100%" stopColor={T.br1} stopOpacity={0}/></linearGradient>
                <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={T.crit} stopOpacity={0.4}/><stop offset="100%" stopColor={T.crit} stopOpacity={0}/></linearGradient>
              </defs>
              <CartesianGrid stroke={T.bd1} strokeDasharray="2 4"/>
              <XAxis dataKey="hour" stroke={T.tx3} fontSize={10} tickLine={false} axisLine={false} fontFamily="JetBrains Mono"/>
              <YAxis yAxisId="l" stroke={T.tx3} fontSize={10} tickLine={false} axisLine={false} tickFormatter={v=>v>=1e6?`${(v/1e6).toFixed(1)}M`:v>=1000?`${(v/1000).toFixed(0)}k`:v}/>
              <YAxis yAxisId="r" orientation="right" stroke={T.tx3} fontSize={10} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={{background:T.bg2,border:`1px solid ${T.bd2}`,fontSize:11,fontFamily:'JetBrains Mono'}}/>
              <Area yAxisId="l" type="monotone" dataKey="events"    stroke={T.br1}  strokeWidth={1.5} fill="url(#gE)"/>
              <Area yAxisId="r" type="monotone" dataKey="alerts"    stroke={T.crit} strokeWidth={1.8} fill="url(#gA)"/>
              <Area yAxisId="r" type="monotone" dataKey="anomalies" stroke={T.ml}   strokeWidth={1.2} fill="none"/>
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card style={{ padding:20, display:'flex', flexDirection:'column' }}>
          <Label>Severity Distribution</Label>
          <div style={{ flex:1, position:'relative', minHeight:220 }}>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" innerRadius={56} outerRadius={84} paddingAngle={2} stroke="none">
                  {pieData.map((e,i)=><Cell key={i} fill={e.color}/>)}
                </Pie>
                <Tooltip contentStyle={{background:T.bg2,border:`1px solid ${T.bd2}`,fontSize:11}}/>
              </PieChart>
            </ResponsiveContainer>
            <div style={{ position:'absolute', inset:0, display:'grid', placeItems:'center', pointerEvents:'none' }}>
              <div style={{ textAlign:'center' }}>
                <div style={{ fontFamily:'Space Grotesk', color:T.tx1, fontSize:28, fontWeight:700 }}>{kpis.active_alerts||0}</div>
                <div style={{ fontFamily:'Space Grotesk', color:T.tx3, fontSize:9, letterSpacing:'0.1em' }}>TOTAL</div>
              </div>
            </div>
          </div>
          <div style={{ display:'flex', justifyContent:'space-around', borderTop:`1px solid ${T.bd1}`, paddingTop:10 }}>
            {pieData.map(s=>(
              <div key={s.name} style={{ textAlign:'center' }}>
                <div style={{ width:7, height:7, borderRadius:'50%', background:s.color, margin:'0 auto 3px'}}/>
                <div style={{ fontFamily:'JetBrains Mono', color:T.tx1, fontSize:13, fontWeight:600 }}>{s.value}</div>
                <div style={{ fontFamily:'Space Grotesk', color:T.tx3, fontSize:8, letterSpacing:'0.06em' }}>{s.name.slice(0,4)}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* MITRE Kill Chain Coverage */}
      <Card style={{ padding:20 }}>
        <div style={{ display:'flex', justifyContent:'space-between', marginBottom:14 }}>
          <div>
            <Label>MITRE ATT&CK Kill Chain Coverage</Label>
            <div style={{ fontFamily:'JetBrains Mono', color:T.tx3, fontSize:10, marginTop:2 }}>Active Sigma rules per tactic</div>
          </div>
        </div>
        <div style={{ display:'flex', gap:8, overflowX:'auto' }}>
          {KILL_CHAIN.map((t, i) => {
            const maxCov = 12;
            const pct = Math.min(t.covered / maxCov, 1);
            const color = pct >= 0.8 ? T.low : pct >= 0.5 ? T.med : T.high;
            return (
              <div key={t.tactic} style={{ flex:1, minWidth:80, padding:'12px 8px', background:T.bg2, borderRadius:6, border:`1px solid ${T.bd1}`, textAlign:'center', cursor:'pointer' }}
                onMouseEnter={e=>e.currentTarget.style.borderColor=color}
                onMouseLeave={e=>e.currentTarget.style.borderColor=T.bd1}>
                <div style={{ height:3, background:T.bd2, borderRadius:2, marginBottom:8, overflow:'hidden' }}>
                  <div style={{ width:`${pct*100}%`, height:'100%', background:`linear-gradient(90deg, ${color}80, ${color})` }}/>
                </div>
                <div style={{ fontFamily:'JetBrains Mono', color, fontSize:16, fontWeight:700 }}>{t.covered}</div>
                <div style={{ fontFamily:'Space Grotesk', color:T.tx3, fontSize:8, letterSpacing:'0.04em', marginTop:4, lineHeight:1.3 }}>{t.tactic}</div>
              </div>
            );
          })}
        </div>
      </Card>

      </div>
    </div>
  );
}

function KpiCard({ label, value, delta, trend, icon:Icon, color, pulse }) {
  return (
    <div style={{ background:T.bg1, border:`1px solid ${T.bd1}`, borderRadius:8, padding:'16px 18px', position:'relative', overflow:'hidden' }}>
      {pulse && <div style={{ position:'absolute', top:0, right:0, bottom:0, width:3, background:color, animation:'pulse-dot 2s infinite' }}/>}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:8 }}>
        <Label>{label}</Label>
        <Icon size={14} color={color} strokeWidth={1.8}/>
      </div>
      <div style={{ fontFamily:'Space Grotesk', color, fontSize:26, fontWeight:700, letterSpacing:'-0.02em' }}>{value}</div>
      <div style={{ marginTop:6, display:'flex', alignItems:'center', gap:4, fontFamily:'JetBrains Mono', fontSize:11 }}>
        {trend==='up' && <TrendingUp size={11} color={T.high}/>}
        {trend==='down' && <TrendingDown size={11} color={T.low}/>}
        <span style={{ color:T.tx2 }}>{delta}</span>
      </div>
    </div>
  );
}

function MetricCard({ label, value, desc, color, icon:Icon }) {
  return (
    <Card style={{ padding:'14px 16px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
        <Label>{label}</Label>
        <Icon size={13} color={color} strokeWidth={1.8}/>
      </div>
      <div style={{ fontFamily:'JetBrains Mono', color, fontSize:24, fontWeight:600 }}>{value}</div>
      <div style={{ color:T.tx3, fontSize:11, marginTop:4 }}>{desc}</div>
    </Card>
  );
}
