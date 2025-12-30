// ===============================================
// Protected Route - Redirect unauthenticated users
// ===============================================

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Loader2 } from 'lucide-react';

const ProtectedRoute = ({ children }) => {
    // TEMPORARILY DISABLED: Authentication bypass for development
    // TODO: Re-enable when backend is ready
    return children;

    /* Original auth check - uncomment when ready:
    const { isAuthenticated, loading } = useAuth();
    const location = useLocation();

    // Show loading spinner while checking auth
    if (loading) {
        return (
            <div className="min-h-screen w-full flex items-center justify-center bg-black">
                <div className="text-center">
                    <Loader2 className="w-12 h-12 text-cyan-500 animate-spin mx-auto mb-4" />
                    <p className="text-gray-400 text-sm">Loading...</p>
                </div>
            </div>
        );
    }

    // Redirect to login if not authenticated
    if (!isAuthenticated) {
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    return children;
    */
};

export default ProtectedRoute;
