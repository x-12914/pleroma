import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'sonner';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import PrivateRoute from './components/PrivateRoute';
import Dashboard from './pages/Dashboard';
import UrlScan from './pages/UrlScan';
import Sensors from './pages/Sensors';
import Logs from './pages/Logs';
import Login from './pages/Login';
import Register from './pages/Register';
import NotFound from './pages/NotFound';
import { AuthProvider } from './context/AuthContext';
import './App.css';

/* Shell — sidebar + navbar + content area, used by all authed routes. */
function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-dvh bg-surface-base text-ink">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Navbar />
        <main className="flex-1 overflow-auto px-4 lg:px-8 py-6 lg:py-8 max-w-screen-2xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public auth pages — no shell */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Authed app — shell wrapper */}
          <Route
            path="/"
            element={<PrivateRoute><AppShell><Dashboard /></AppShell></PrivateRoute>}
          />
          <Route
            path="/url-scan"
            element={<PrivateRoute><AppShell><UrlScan /></AppShell></PrivateRoute>}
          />
          <Route
            path="/sensors"
            element={<PrivateRoute><AppShell><Sensors /></AppShell></PrivateRoute>}
          />
          <Route
            path="/logs"
            element={<PrivateRoute><AppShell><Logs /></AppShell></PrivateRoute>}
          />

          {/* Real 404 — no silent redirect to / */}
          <Route path="*" element={<NotFound />} />
        </Routes>

        <Toaster
          richColors
          position="top-right"
          theme="dark"
          toastOptions={{
            style: {
              background: '#1a1a1d',
              border: '1px solid #26262a',
              color: '#f5f5f6',
              fontSize: '13px',
            },
          }}
        />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
