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
    // Auth lives in an httpOnly cookie now (not JS-readable). Ask the server who
    // we are — if the cookie is valid, /me returns the user; otherwise we're anon.
    const initAuth = async () => {
      try {
        const res = await authService.getMe();
        setUser(res.data);
        setIsAuthenticated(true);
      } catch {
        setUser(null);
        setIsAuthenticated(false);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  // -----------------------------
  // LOGIN
  // -----------------------------
  const login = async (email: string, password: string) => {
    setLoading(true);

    try {
      // Login sets the httpOnly auth cookie server-side; we don't touch the token.
      await authService.login(email.trim(), password);
      // Fetch the full user record (id, email, role) so the UI has it immediately.
      const me = await authService.getMe();
      setUser(me.data);
      setIsAuthenticated(true);
    } catch (error: any) {
      setIsAuthenticated(false);
      setUser(null);
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
    // Fire-and-forget: tell the server to clear the httpOnly cookie.
    authService.logout().catch(() => { /* ignore */ });
    setUser(null);
    setIsAuthenticated(false);
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