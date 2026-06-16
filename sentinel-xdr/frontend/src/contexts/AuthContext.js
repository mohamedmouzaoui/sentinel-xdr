import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const stored = localStorage.getItem('sentinel_user');
    const token  = localStorage.getItem('sentinel_token');
    if (stored && token) {
      setUser(JSON.parse(stored));
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    setLoading(false);
  }, []);

  const login = useCallback(async (username, password) => {
    const { data } = await api.post('/auth/login', { username, password });
    localStorage.setItem('sentinel_token', data.access_token);
    localStorage.setItem('sentinel_refresh', data.refresh_token);
    localStorage.setItem('sentinel_user', JSON.stringify(data.user));
    api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`;
    setUser(data.user);
    return data.user;
  }, []);

  const logout = useCallback(async () => {
    try { await api.post('/auth/logout'); } catch {}
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_refresh');
    localStorage.removeItem('sentinel_user');
    delete api.defaults.headers.common['Authorization'];
    setUser(null);
  }, []);

  const canDo = useCallback((minRole) => {
    const hierarchy = { superadmin:6, admin:5, analyst_l3:4, analyst_l2:3, analyst_l1:2, readonly:1 };
    return (hierarchy[user?.role] || 0) >= (hierarchy[minRole] || 0);
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, canDo }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
