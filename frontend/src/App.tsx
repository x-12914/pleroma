import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
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
import { AuthProvider } from './context/AuthContext';
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
            {/* Public routes */}
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* Protected routes - Dashboard and pages */}
            <Route
              path="/*"
              element={
                <PrivateRoute>
                  <div className="flex h-screen bg-dark-950">
                    {/* Sidebar */}
                    <Sidebar />

                    {/* Main Content */}
                    <div className="flex-1 flex flex-col overflow-hidden">
                      {/* Navbar */}
                      <Navbar />

                      {/* Page Content */}
                      <main className="flex-1 overflow-auto p-4 md:p-8">
                        <Routes>
                          <Route path="/" element={<Dashboard />} />
                          <Route path="/url-scan" element={<UrlScan />} />
                          <Route path="/sensors" element={<Sensors />} />
                          <Route path="/logs" element={<Logs />} />
                        </Routes>
                      </main>
                    </div>
                  </div>
                </PrivateRoute>
              }
            />

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          <Toaster richColors position="top-right" />
        </AuthProvider>
      </BrowserRouter>
    );
}

export default App;
