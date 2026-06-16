import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react';

const T = {
  bg0:'#070a0e', bg1:'#0c1117', bg2:'#11171f', bd1:'#1d2533',
  br1:'#22d3ee', tx1:'#e5edf5', tx2:'#9aa8bd', tx3:'#5d6d85',
  crit:'#ff5c7c',
};

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', password: '' });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      await login(form.username, form.password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh', background: T.bg0, display: 'flex',
      alignItems: 'center', justifyContent: 'center',
      fontFamily: 'Inter, sans-serif',
      backgroundImage: `radial-gradient(ellipse 60% 60% at 50% 0%, ${T.br1}12, transparent)`,
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@700&display=swap');
        * { box-sizing: border-box; }
        @keyframes float-up { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
        .login-card { animation: float-up 0.5s ease-out; }
      `}</style>

      <div className="login-card" style={{ width: 420, padding: 40, background: T.bg1, border: `1px solid ${T.bd1}`, borderRadius: 12, boxShadow: `0 0 80px ${T.br1}1a` }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 12, margin: '0 auto 14px',
            background: `linear-gradient(135deg, ${T.br1}, #0891b2)`,
            display: 'grid', placeItems: 'center',
            boxShadow: `0 0 32px ${T.br1}40`,
          }}>
            <Shield size={28} color={T.bg0} strokeWidth={2.5} />
          </div>
          <div style={{ fontFamily: 'Space Grotesk', color: T.tx1, fontSize: 22, fontWeight: 700, letterSpacing: '0.04em' }}>SENTINEL XDR</div>
          <div style={{ fontFamily: 'JetBrains Mono', color: T.tx3, fontSize: 10, marginTop: 4, letterSpacing: '0.1em' }}>SECURITY OPERATIONS CENTER · v3.0</div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          {error && (
            <div style={{ background: `${T.crit}18`, border: `1px solid ${T.crit}50`, borderRadius: 6, padding: '10px 14px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertCircle size={14} color={T.crit} />
              <span style={{ color: T.crit, fontSize: 13 }}>{error}</span>
            </div>
          )}

          <label style={{ display: 'block', marginBottom: 16 }}>
            <div style={{ color: T.tx3, fontSize: 11, fontFamily: 'Space Grotesk', fontWeight: 700, letterSpacing: '0.06em', marginBottom: 6 }}>USERNAME</div>
            <input
              type="text"
              value={form.username}
              onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              placeholder="analyst.l2"
              style={{
                width: '100%', background: T.bg0, border: `1px solid ${T.bd1}`,
                borderRadius: 6, padding: '10px 14px', color: T.tx1,
                fontFamily: 'JetBrains Mono', fontSize: 13, outline: 'none',
              }}
              onFocus={e => e.target.style.borderColor = T.br1}
              onBlur={e => e.target.style.borderColor = T.bd1}
              required
            />
          </label>

          <label style={{ display: 'block', marginBottom: 24, position: 'relative' }}>
            <div style={{ color: T.tx3, fontSize: 11, fontFamily: 'Space Grotesk', fontWeight: 700, letterSpacing: '0.06em', marginBottom: 6 }}>PASSWORD</div>
            <input
              type={showPw ? 'text' : 'password'}
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              placeholder="••••••••••••"
              style={{
                width: '100%', background: T.bg0, border: `1px solid ${T.bd1}`,
                borderRadius: 6, padding: '10px 40px 10px 14px', color: T.tx1,
                fontFamily: 'JetBrains Mono', fontSize: 13, outline: 'none',
              }}
              onFocus={e => e.target.style.borderColor = T.br1}
              onBlur={e => e.target.style.borderColor = T.bd1}
              required
            />
            <button type="button" onClick={() => setShowPw(!showPw)} style={{
              position: 'absolute', right: 12, top: 34, background: 'none', border: 'none',
              cursor: 'pointer', color: T.tx3, padding: 2,
            }}>
              {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </label>

          <button type="submit" disabled={loading} style={{
            width: '100%', background: loading ? T.tx3 : `linear-gradient(135deg, ${T.br1}, #0891b2)`,
            border: 'none', borderRadius: 6, padding: '12px',
            color: T.bg0, fontFamily: 'Space Grotesk', fontSize: 13, fontWeight: 700,
            letterSpacing: '0.06em', cursor: loading ? 'not-allowed' : 'pointer',
            transition: 'opacity 0.15s',
          }}>
            {loading ? 'AUTHENTICATING...' : 'SIGN IN TO SOC'}
          </button>
        </form>

        <div style={{ marginTop: 20, padding: '12px 14px', background: T.bg2, borderRadius: 6, border: `1px solid ${T.bd1}` }}>
          <div style={{ fontFamily: 'JetBrains Mono', color: T.tx3, fontSize: 10, marginBottom: 4, letterSpacing: '0.06em' }}>DEFAULT CREDENTIALS</div>
          <div style={{ fontFamily: 'JetBrains Mono', color: T.tx2, fontSize: 11 }}>admin / SentinelXDR@2024!</div>
        </div>
      </div>
    </div>
  );
}
