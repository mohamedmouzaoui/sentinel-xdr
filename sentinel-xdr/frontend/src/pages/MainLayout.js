import React, { useState, useEffect, useCallback } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  Shield, Activity, ShieldAlert, Layers, Network, Zap,
  FileCode, BookOpen, Terminal, Bell, User, LogOut,
  ChevronDown, Database, Cloud, Search, Wifi, WifiOff
} from 'lucide-react';

const T = {
  bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bg3:'#1a2230',
  bd1:'#1d2533', bd2:'#2a3445',
  br1:'#22d3ee', br3:'#0891b2', brGlow:'#22d3ee20',
  tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85',
  crit:'#ff5c7c', high:'#ff9544', low:'#3ddc97',
};

const NAV = [
  { to: '/dashboard', label: 'Command Center',    icon: Activity },
  { to: '/alerts',    label: 'Alerts',             icon: ShieldAlert },
  { to: '/incidents', label: 'Incidents',          icon: Layers },
  { to: '/iocs',      label: 'CTI / IoC',          icon: Network },
  { to: '/playbooks', label: 'SOAR Playbooks',     icon: Zap },
  { to: '/rules',     label: 'Rules & ML',         icon: FileCode },
  { to: '/audit',     label: 'Audit Log',          icon: BookOpen },
];

export default function MainLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [notifications, setNotifications] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [liveAlerts, setLiveAlerts] = useState([]);

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'connected') {
      setWsConnected(true);
    } else if (msg.type === 'alert_new') {
      setLiveAlerts(prev => [msg, ...prev].slice(0, 20));
      setNotifications(prev => [{ id: Date.now(), text: msg.title || 'New alert', sev: msg.severity }, ...prev].slice(0, 5));
    }
  }, []);

  useWebSocket(handleWsMessage);

  return (
    <div style={{ display: 'flex', height: '100vh', background: T.bg0, fontFamily: 'Inter, sans-serif', color: T.tx1 }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; }
        .nav-link { display:flex; align-items:center; gap:12px; padding:9px 12px; border-radius:5px; font-size:12.5px; font-weight:500; color:${T.tx2}; text-decoration:none; border-left:2px solid transparent; transition:all 0.12s; margin-bottom:2px; }
        .nav-link:hover { background:${T.bg2}; color:${T.tx1}; }
        .nav-link.active { background:${T.bg3}; color:${T.br1}; font-weight:600; border-left-color:${T.br1}; }
        .scrollbar::-webkit-scrollbar { width:6px; }
        .scrollbar::-webkit-scrollbar-track { background:${T.bg1}; }
        .scrollbar::-webkit-scrollbar-thumb { background:${T.bd2}; border-radius:3px; }
        @keyframes pulse-dot { 0%,100%{transform:scale(1);opacity:1} 50%{transform:scale(1.5);opacity:0.5} }
        .pulse { animation: pulse-dot 2s ease-in-out infinite; }
        @keyframes slide-in { from{transform:translateX(20px);opacity:0} to{transform:translateX(0);opacity:1} }
        .slide-in { animation: slide-in 0.3s ease-out; }
      `}</style>

      {/* Sidebar */}
      <aside style={{ width: 232, background: T.bg1, borderRight: `1px solid ${T.bd1}`, display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        {/* Brand */}
        <div style={{ padding: '20px 20px 24px', borderBottom: `1px solid ${T.bd1}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 34, height: 34, borderRadius: 8,
              background: `linear-gradient(135deg, ${T.br1}, ${T.br3})`,
              display: 'grid', placeItems: 'center',
              boxShadow: `0 0 20px ${T.brGlow}`,
            }}>
              <Shield size={18} color={T.bg0} strokeWidth={2.5} />
            </div>
            <div>
              <div style={{ fontFamily: 'Space Grotesk', color: T.tx1, fontWeight: 700, fontSize: 14, letterSpacing: '0.05em' }}>SENTINEL</div>
              <div style={{ fontFamily: 'JetBrains Mono', color: T.br1, fontSize: 9, letterSpacing: '0.12em' }}>XDR PRO · v3.0</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }} className="scrollbar">
          {NAV.map(n => (
            <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              <n.icon size={15} strokeWidth={1.8} />
              {n.label}
            </NavLink>
          ))}
        </nav>

        {/* Status footer */}
        <div style={{ padding: 14, borderTop: `1px solid ${T.bd1}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            {wsConnected
              ? <><span style={{ width: 6, height: 6, borderRadius: '50%', background: T.low }} className="pulse" /><span style={{ fontFamily: 'JetBrains Mono', color: T.low, fontSize: 9, letterSpacing: '0.08em' }}>LIVE · CONNECTED</span></>
              : <><WifiOff size={10} color={T.tx3} /><span style={{ fontFamily: 'JetBrains Mono', color: T.tx3, fontSize: 9 }}>OFFLINE</span></>
            }
          </div>

          {/* User */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${T.br1}30`, border: `1px solid ${T.br1}60`, display: 'grid', placeItems: 'center' }}>
              <User size={13} color={T.br1} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: T.tx1, fontSize: 12, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user?.username}</div>
              <div style={{ fontFamily: 'JetBrains Mono', color: T.tx3, fontSize: 9, letterSpacing: '0.04em' }}>{user?.role?.replace('_', ' ').toUpperCase()}</div>
            </div>
            <button onClick={logout} style={{ background: 'none', border: 'none', cursor: 'pointer', color: T.tx3, padding: 4, borderRadius: 3 }}
              title="Logout">
              <LogOut size={13} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Topbar */}
        <header style={{ height: 56, background: T.bg1, borderBottom: `1px solid ${T.bd1}`, display: 'flex', alignItems: 'center', padding: '0 24px', gap: 20, flexShrink: 0 }}>
          <div style={{ flex: 1, maxWidth: 520, display: 'flex', alignItems: 'center', gap: 8, background: T.bg0, border: `1px solid ${T.bd1}`, borderRadius: 5, padding: '0 12px' }}>
            <Search size={13} color={T.tx3} />
            <input placeholder="Search · ip, hash, rule, incident..." style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: T.tx1, fontSize: 12, fontFamily: 'JetBrains Mono', padding: '9px 0' }} />
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <div style={{ position: 'relative' }}>
              <button style={{ width: 34, height: 34, background: 'none', border: 'none', color: T.tx2, cursor: 'pointer', display: 'grid', placeItems: 'center', borderRadius: 4 }}>
                <Bell size={15} />
              </button>
              {notifications.length > 0 && (
                <span style={{ position: 'absolute', top: 8, right: 8, width: 6, height: 6, borderRadius: '50%', background: T.crit }} className="pulse" />
              )}
            </div>
            <div style={{ fontFamily: 'JetBrains Mono', color: T.tx3, fontSize: 10, borderLeft: `1px solid ${T.bd2}`, paddingLeft: 12 }}>
              {user?.tenant_id?.replace('tenant_', '').toUpperCase()}
            </div>
          </div>
        </header>

        {/* Page content */}
        <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }} className="scrollbar">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
