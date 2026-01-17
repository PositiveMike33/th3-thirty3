// ===============================================
// Auth Context - Global Authentication State
// Provides login, logout, register functions app-wide
// ===============================================

/* eslint-disable react-refresh/only-export-components */
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { API_URL } from '../config';

const AuthContext = createContext(null);

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(localStorage.getItem('nexus33_token'));
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Check if user is authenticated on mount
    useEffect(() => {
        const checkAuth = async () => {
            const savedToken = localStorage.getItem('nexus33_token');
            if (savedToken) {
                try {
                    const response = await fetch(`${API_URL}/auth/me`, {
                        headers: {
                            'Authorization': `Bearer ${savedToken}`
                        }
                    });
                    const data = await response.json();

                    if (data.success && data.user) {
                        setUser(data.user);
                        setToken(savedToken);
                    } else {
                        // Token invalid, clear it
                        localStorage.removeItem('nexus33_token');
                        setToken(null);
                        setUser(null);
                    }
                } catch (err) {
                    console.error('[AUTH] Token verification failed:', err);
                    localStorage.removeItem('nexus33_token');
                    setToken(null);
                    setUser(null);
                }
            }
            setLoading(false);
        };

        checkAuth();
    }, []);

    // Listen for automatic logout events (from API service when token expires)
    useEffect(() => {
        const handleAutoLogout = () => {
            console.log('[AUTH] Auto-logout triggered (token expired)');
            setUser(null);
            setToken(null);
            setError('Session expired. Please log in again.');
        };

        window.addEventListener('auth:logout', handleAutoLogout);
        return () => window.removeEventListener('auth:logout', handleAutoLogout);
    }, []);

    // Login function - DEBUG v1.2.1-debug
    const login = useCallback(async (email, password) => {
        setError(null);
        setLoading(true);

        // [DEBUG] Log payload being sent
        const payload = { email, password };
        console.log('[AUTH DEBUG v1.2.1] Login attempt:', {
            endpoint: `${API_URL}/auth/login`,
            payload: { email, passwordLength: password?.length || 0 },
            timestamp: new Date().toISOString()
        });

        try {
            const response = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            // [DEBUG] Log response status and headers
            console.log('[AUTH DEBUG v1.2.1] Response received:', {
                status: response.status,
                statusText: response.statusText,
                ok: response.ok,
                headers: Object.fromEntries(response.headers.entries())
            });

            const data = await response.json();

            // [DEBUG] Log full response data
            console.log('[AUTH DEBUG v1.2.1] Response body:', {
                success: data.success,
                hasToken: !!data.token,
                hasUser: !!data.user,
                error: data.error || null,
                fullData: data
            });

            if (data.success) {
                setUser(data.user);
                setToken(data.token);
                localStorage.setItem('nexus33_token', data.token);
                console.log('[AUTH DEBUG v1.2.1] ✅ Login SUCCESS - Token stored');
                return { success: true };
            } else {
                console.log('[AUTH DEBUG v1.2.1] ❌ Login FAILED:', data.error);
                setError(data.error);
                return { success: false, error: data.error };
            }
        } catch (err) {
            console.error('[AUTH DEBUG v1.2.1] ❌ Login EXCEPTION:', err);
            const errorMsg = 'Connection failed. Please try again.';
            setError(errorMsg);
            return { success: false, error: errorMsg };
        } finally {
            setLoading(false);
        }
    }, []);

    // Register function
    const register = useCallback(async (username, email, password, firstName, lastName) => {
        setError(null);
        setLoading(true);

        try {
            const response = await fetch(`${API_URL}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password, firstName, lastName })
            });

            const data = await response.json();

            if (data.success) {
                setUser(data.user);
                setToken(data.token);
                localStorage.setItem('nexus33_token', data.token);
                return { success: true };
            } else {
                setError(data.error);
                return { success: false, error: data.error };
            }
        } catch {
            const errorMsg = 'Registration failed. Please try again.';
            setError(errorMsg);
            return { success: false, error: errorMsg };
        } finally {
            setLoading(false);
        }
    }, []);

    // Logout function
    const logout = useCallback(() => {
        setUser(null);
        setToken(null);
        localStorage.removeItem('nexus33_token');
        setError(null);
    }, []);

    // Update profile
    const updateProfile = useCallback(async (updates) => {
        if (!token) return { success: false, error: 'Not authenticated' };

        try {
            const response = await fetch(`${API_URL}/auth/profile`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(updates)
            });

            const data = await response.json();

            if (data.success) {
                setUser(data.user);
                return { success: true };
            } else {
                return { success: false, error: data.error };
            }
        } catch {
            return { success: false, error: 'Update failed' };
        }
    }, [token]);

    const value = {
        user,
        token,
        loading,
        error,
        isAuthenticated: !!user,
        login,
        logout,
        register,
        updateProfile,
        clearError: () => setError(null)
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};

export default AuthContext;
