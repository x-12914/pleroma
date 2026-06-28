import axios from 'axios';

// 1. Setup Base URL with the Vite env fallback.
// In production the frontend is served from the same origin as the API
// (https://pleroma-aicds.duckdns.org), so the default points there.
// For local development, set VITE_API_BASE_URL=http://localhost:8000/api/v1
// in frontend/.env.local.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://pleroma-aicds.duckdns.org/api/v1';
const API_ROOT = API_BASE_URL.replace(/\/api\/v1\/?$/, '');

const api = axios.create({
  baseURL: API_BASE_URL,
  // Send the httpOnly auth cookie with every request (auto on same-origin; this
  // also covers cross-origin dev). Auth is now cookie-based — the JWT is never
  // stored in JS, so an XSS can't read it.
  withCredentials: true,
});

// 2. Single Request Interceptor: trailing slashes only (auth rides the cookie).
api.interceptors.request.use((config) => {
  // Prevent 307 Redirects for iOS by ensuring POST URLs always end with a slash.
  if (config.method?.toLowerCase() === 'post' && config.url) {
    const [path, query] = config.url.split('?');
    if (!path.endsWith('/')) {
      config.url = `${path}/${query ? `?${query}` : ''}`;
    }
  }
  return config;
});

// 3. Single Response Interceptor: Handles Session Expiration (Auto-Logout)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.warn("Session expired. Redirecting to login...");
      // Only redirect if we aren't already on the login page
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// 4. Analysis Endpoints

export interface ScanSource {
  src_ip: string;
  detections: number;
  classes: string[];
  ports: number;
  verdict: string;
  first_seen: string;
  last_seen: string;
}

export const analysisService = {
  // Start Analysis
  startUrlScan: (url: string) => api.post('/analysis/url/', { url }),
  startNetworkScan: (record: any) => api.post('/analysis/network/', { record }),
  
  // Check Status (Polling)
  getTaskStatus: (taskId: string) => api.get(`/analysis/status/${taskId}`),
  
  // Dashboard & Logs
  getStats: () => api.get('/logs/stats'),
  
  // We provide both names so Dashboard.tsx and Logs.tsx both work without errors
  getHistory: (limit = 10, offset = 0) => api.get(`/logs/?limit=${limit}&offset=${offset}`),
  getLogs: (limit = 10, offset = 0) => api.get(`/logs/?limit=${limit}&offset=${offset}`),

  // Aggregated "by source" view — network detections grouped per source IP.
  getScanSources: (hours = 24, limit = 100) =>
    api.get<ScanSource[]>(`/logs/sources?hours=${hours}&limit=${limit}`),
  
  // Admin
  retrainModel: () => api.post('/analysis/network/retrain/'),
  submitLogFeedback: (logId: number, payload: any) => api.post(`/logs/${logId}/feedback/`, payload),
};

// 5. System Health (Used for the Online/Offline indicator)
// Derived from API_BASE_URL so there's one source of truth for the API host.
export const checkSystemHealth = () => axios.get(`${API_ROOT}/`);

// 6. Sensor Management Endpoints
export const sensorService = {
  list: () => api.get('/sensors/'),
  create: (name: string) => api.post('/sensors/', { name }),
  remove: (id: number) => api.delete(`/sensors/${id}`),
};

// 7. Authentication Endpoints
export const authService = {
  login: (email: string, password: string) => {
    // FastAPI OAuth2 requires Form Data (URLSearchParams)
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);
    return api.post('/auth/login/', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
  },
  register: (data: any) => {
    // Registration uses standard JSON (matching our UserCreate Pydantic model)
    return api.post('/auth/register/', data);
  },
  getMe: () => api.get('/me'), // Matches the @app.get("/me") in main.py
  logout: () => api.post('/auth/logout'), // Clears the httpOnly auth cookie
};

// 8. Autonomous Response Endpoints (Phase 2 — see docs/CONTRACTS.md §5)
// Admin-gated mutations, analyst+ reads. All under /api/v1/response.

export type ResponseMode = 'off' | 'dry_run' | 'recommend' | 'auto';

export type ActionType = 'block' | 'throttle' | 'alert' | 'host';

export type ActionStatus =
  | 'would_apply'
  | 'pending'
  | 'active'
  | 'expired'
  | 'reverted'
  | 'rejected'
  | 'failed';

export interface EnforcementState {
  mode: ResponseMode;
  kill_switch: boolean;
  updated_at?: string;
  updated_by?: string;
}

export interface AllowlistEntry {
  id: number;
  cidr: string;
  reason: string;
  created_by?: string;
  created_at?: string;
}

export interface PolicyRule {
  id: number;
  name: string;
  enabled: boolean;
  priority?: number;
  match_raw_class?: string | null;
  match_verdict?: string | null;
  min_confidence?: number;
  min_repeats?: number;
  window_seconds?: number;
  action: ActionType;
  action_params?: Record<string, unknown>;
  mode_override?: ResponseMode | null;
  created_at?: string;
  updated_at?: string;
}

export interface ResponseAction {
  id: number;
  ts: string;
  src_ip: string | null;
  action_type: ActionType;
  raw_class: string | null;
  confidence: number | null;
  reason: string | null;
  mode: string;
  status: ActionStatus;
  expires_at: string | null;
  created_by: string | null;
}

export const responseService = {
  // Enforcement state (mode + kill switch)
  getState: () => api.get<EnforcementState>('/response/state'),
  updateState: (payload: { mode: ResponseMode; kill_switch: boolean }) =>
    api.put<EnforcementState>('/response/state', payload),

  // Allowlist — IPs/CIDRs never acted on
  getAllowlist: () => api.get<AllowlistEntry[]>('/response/allowlist'),
  addAllowlist: (payload: { cidr: string; reason: string }) =>
    api.post<AllowlistEntry>('/response/allowlist', payload),
  removeAllowlist: (id: number) => api.delete(`/response/allowlist/${id}`),

  // Policy rules
  getPolicy: () => api.get<PolicyRule[]>('/response/policy'),
  createPolicy: (payload: Partial<PolicyRule>) =>
    api.post<PolicyRule>('/response/policy', payload),
  updatePolicy: (id: number, payload: Partial<PolicyRule>) =>
    api.put<PolicyRule>(`/response/policy/${id}`, payload),
  removePolicy: (id: number) => api.delete(`/response/policy/${id}`),

  // Actions — audit + work queue
  getActions: (status?: ActionStatus) =>
    api.get<ResponseAction[]>('/response/actions', {
      params: status ? { status } : undefined,
    }),
  approveAction: (id: number) => api.post(`/response/actions/${id}/approve`),
  rejectAction: (id: number) => api.post(`/response/actions/${id}/reject`),
  revertAction: (id: number) => api.post(`/response/actions/${id}/revert`),
};

export default api;