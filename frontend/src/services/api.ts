import axios from 'axios';

// 1. Setup Base URL with the Vite env fallback
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://aicds-backend-main.onrender.com/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
});

// 2. Single Request Interceptor: Handles Token + Trailing Slashes
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  // Prevent 307 Redirects for iOS by ensuring POST URLs always end with a slash.
  if (config.method?.toLowerCase() === 'post' && config.url) {
    const [path, query] = config.url.split('?');
    if (!path.endsWith('/')) {
      config.url = `${path}/${query ? `?${query}` : ''}`;
    }
  }
  return config;
});

// 3. Single Response Interceptor: Handles Token Expiration (Auto-Logout)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.warn("Session expired. Redirecting to login...");
      localStorage.removeItem('token');
      // Only redirect if we aren't already on the login page
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// 4. Analysis Endpoints

export const analysisService = {
  // Start Analysis
  startUrlScan: (url: string) => api.post('/analysis/url/', { url }),
  startNetworkScan: (record: any) => api.post('/analysis/network/', { record }),
  
  // Check Status (Polling)
  getTaskStatus: (taskId: string) => api.get(`/analysis/status/${taskId}`),
  
  // Dashboard & Logs
  getStats: () => api.get('/logs/stats'),
  
  // We provide both names so Dashboard.tsx and Logs.tsx both work without errors
  getHistory: (limit = 10) => api.get(`/logs/?limit=${limit}`),
  getLogs: (limit = 10) => api.get(`/logs/?limit=${limit}`), 
  
  // Admin
  retrainModel: () => api.post('/analysis/network/retrain/'),
  submitLogFeedback: (logId: number, payload: any) => api.post(`/logs/${logId}/feedback/`, payload),
};

// 5. System Health (Used for the Online/Offline indicator)
export const checkSystemHealth = () => axios.get('https://aicds-backend-main.onrender.com/');

// 6. Authentication Endpoints
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
};

export default api;