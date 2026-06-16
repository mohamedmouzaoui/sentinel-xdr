import axios from 'axios';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || '/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// Auto-attach token
api.interceptors.request.use(config => {
  const token = localStorage.getItem('sentinel_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  res => res,
  async err => {
    if (err.response?.status === 401 && !err.config._retry) {
      err.config._retry = true;
      const refresh = localStorage.getItem('sentinel_refresh');
      if (refresh) {
        try {
          const { data } = await axios.post('/api/v1/auth/refresh', { refresh_token: refresh });
          localStorage.setItem('sentinel_token', data.access_token);
          api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`;
          err.config.headers['Authorization'] = `Bearer ${data.access_token}`;
          return api(err.config);
        } catch {
          localStorage.clear();
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(err);
  }
);

export default api;

// ── Service functions ─────────────────────────────────────────────────────────
export const authService = {
  login:  (username, password) => api.post('/auth/login', { username, password }),
  me:     () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
};

export const dashboardService = {
  overview: () => api.get('/dashboard/overview'),
};

export const alertsService = {
  list:          (params) => api.get('/alerts', { params }),
  get:           (id)     => api.get(`/alerts/${id}`),
  stats:         ()       => api.get('/alerts/stats'),
  acknowledge:   (id, reason) => api.patch(`/alerts/${id}/acknowledge`, { reason }),
  falsePositive: (id, reason) => api.patch(`/alerts/${id}/false-positive`, { reason }),
};

export const incidentsService = {
  list:         (params) => api.get('/incidents', { params }),
  get:          (id)     => api.get(`/incidents/${id}`),
  stats:        ()       => api.get('/incidents/stats'),
  updateStatus: (id, status, reason, comment) => api.patch(`/incidents/${id}/status`, { status, reason, comment }),
  assign:       (id, assignee_id, comment)    => api.patch(`/incidents/${id}/assign`, { assignee_id, comment }),
  addComment:   (id, body) => api.post(`/incidents/${id}/comment`, { body }),
};

export const iocsService = {
  list:        (params) => api.get('/iocs', { params }),
  stats:       ()       => api.get('/iocs/stats'),
  create:      (data)   => api.post('/iocs', data),
  update:      (id, d)  => api.patch(`/iocs/${id}`, d),
  remove:      (id)     => api.delete(`/iocs/${id}`),
  bulkImport:  (items)  => api.post('/iocs/bulk-import', items),
};

export const playbooksService = {
  list:    ()                          => api.get('/playbooks'),
  execute: (id, incident_id, target)   => api.post(`/playbooks/${id}/execute`, { incident_id, target }),
};

export const auditService = {
  list: (params) => api.get('/audit-logs', { params }),
};

export const reportsService = {
  incidentPdf:  (id)  => api.get(`/reports/incident/${id}/pdf`, { responseType: 'blob' }),
  weeklyPdf:    ()    => api.get('/reports/weekly/pdf', { responseType: 'blob' }),
  weeklyJson:   ()    => api.get('/reports/weekly/json'),
};
