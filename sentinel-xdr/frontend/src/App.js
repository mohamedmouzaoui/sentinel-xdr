import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import LoginPage from './pages/Login';
import MainLayout from './pages/MainLayout';
import DashboardPage from './pages/Dashboard';
import AlertsPage from './pages/Alerts';
import IncidentsPage from './pages/Incidents';
import IoCsPage from './pages/IoCs';
import PlaybooksPage from './pages/Playbooks';
import AuditPage from './pages/AuditLog';
import RulesPage from './pages/Rules';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return (
    <div style={{ height: '100vh', display: 'grid', placeItems: 'center', background: '#070a0e' }}>
      <div style={{ color: '#22d3ee', fontFamily: 'monospace', fontSize: 13 }}>
        ● Loading Sentinel XDR...
      </div>
    </div>
  );
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard"  element={<DashboardPage />} />
            <Route path="alerts"     element={<AlertsPage />} />
            <Route path="incidents"  element={<IncidentsPage />} />
            <Route path="iocs"       element={<IoCsPage />} />
            <Route path="playbooks"  element={<PlaybooksPage />} />
            <Route path="rules"      element={<RulesPage />} />
            <Route path="audit"      element={<AuditPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
