import React, { createContext, useContext, useState, useEffect } from "react";
import { authService } from "../services/api";

// -----------------------------
// Types
// -----------------------------
interface User {
  email: string;
  is_admin?: boolean;
}

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

// -----------------------------
// Context
// -----------------------------
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// -----------------------------
// Provider
// -----------------------------
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // -----------------------------
  // Load session on mount
  // -----------------------------
  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('token');
      const storedUser = localStorage.getItem('user');

      if (token && storedUser) {
        try {
          const parsedUser = JSON.parse(storedUser);
          setUser(parsedUser);
          setIsAuthenticated(true);
        } catch {
          // ignore malformed stored state
        }
      }

      if (token) {
        try {
          const res = await authService.getMe();
          setUser(res.data);
          setIsAuthenticated(true);
        } catch (error) {
          console.error('Session expired or invalid', error);
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          setUser(null);
          setIsAuthenticated(false);
        }
      }

      setLoading(false);
    };

    initAuth();
  }, []);

  // -----------------------------
  // LOGIN
  // -----------------------------
  const login = async (email: string, password: string) => {
    setLoading(true);

    try {
      const { data } = await authService.login(email.trim(), password);
      localStorage.setItem('token', data.access_token);
      // /auth/login returns only the token, so fetch /me to get the full
      // user record (id, email, is_admin). Without this the admin role
      // never propagates until a page refresh.
      const me = await authService.getMe();
      setUser(me.data);
      localStorage.setItem('user', JSON.stringify(me.data));
      setIsAuthenticated(true);
    } catch (error: any) {
      setIsAuthenticated(false);
      setUser(null);
      localStorage.removeItem('token');
      localStorage.removeItem('user');

      console.error("Login error:", error?.response?.data || error.message);

      throw error;
    } finally {
      setLoading(false);
    }
  };

  // -----------------------------
  // LOGOUT
  // -----------------------------
  const logout = () => {
    setUser(null);
    setIsAuthenticated(false);

    localStorage.removeItem("user");
    localStorage.removeItem("token");
  };

  // -----------------------------
  // Provider Value
  // -----------------------------
  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        user,
        login,
        logout,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// -----------------------------
// Hook
// -----------------------------
export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  return context;
};