import React, { createContext, useContext, useState, useEffect } from "react";
import { authService } from "../services/api";

// -----------------------------
// Types
// -----------------------------
export type Role = 'viewer' | 'analyst' | 'admin';

interface User {
  id?: number;
  email: string;
  is_admin?: boolean;
  role?: Role;
}

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  loading: boolean;
  // True if the user holds at least the given role. Treats older accounts
  // (no role field) as 'analyst' so existing sessions don't lose access.
  hasRole: (min: Role) => boolean;
}

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

function userRole(u: User | null): Role {
  if (!u) return 'viewer';
  if (u.role && ROLE_RANK[u.role]) return u.role;
  return u.is_admin ? 'admin' : 'analyst';
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
  // Role check
  // -----------------------------
  const hasRole = (min: Role): boolean => {
    return ROLE_RANK[userRole(user)] >= ROLE_RANK[min];
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
        hasRole,
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