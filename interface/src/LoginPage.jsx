// ===============================================
// Login Page - Premium Authentication UI
// Modern, animated, responsive login/register form
// ===============================================

import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from './contexts/AuthContext';
import { 
    Eye, EyeOff, Mail, Lock, User, ArrowRight, 
    Loader2, AlertCircle, CheckCircle, Sparkles,
    Shield, Zap, Brain, Globe
} from 'lucide-react';

const LoginPage = () => {
    const { login, register, error, loading, clearError, isAuthenticated } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();
    
    // Redirect if already authenticated
    useEffect(() => {
        if (isAuthenticated) {
            const from = location.state?.from?.pathname || '/';
            navigate(from, { replace: true });
        }
    }, [isAuthenticated, navigate, location]);
    const [isRegister, setIsRegister] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [success, setSuccess] = useState('');
    
    // Form state
    const [formData, setFormData] = useState({
        email: '',
        password: '',
        username: '',
        firstName: '',
        lastName: '',
        confirmPassword: ''
    });

    const [formErrors, setFormErrors] = useState({});

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
        setFormErrors(prev => ({ ...prev, [name]: '' }));
        clearError();
    };

    const validateForm = () => {
        const errors = {};

        if (!formData.email) {
            errors.email = 'Email is required';
        } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
            errors.email = 'Invalid email format';
        }

        if (!formData.password) {
            errors.password = 'Password is required';
        } else if (formData.password.length < 6) {
            errors.password = 'Password must be at least 6 characters';
        }

        if (isRegister) {
            if (!formData.username) {
                errors.username = 'Username is required';
            } else if (formData.username.length < 3) {
                errors.username = 'Username must be at least 3 characters';
            }

            if (formData.password !== formData.confirmPassword) {
                errors.confirmPassword = 'Passwords do not match';
            }
        }

        setFormErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        
        if (!validateForm()) return;

        let result;
        
        if (isRegister) {
            result = await register(
                formData.username,
                formData.email,
                formData.password,
                formData.firstName,
                formData.lastName
            );
        } else {
            result = await login(formData.email, formData.password);
        }

        if (result.success) {
            setSuccess(isRegister ? 'Account created! Welcome aboard.' : 'Login successful!');
            // Redirect to the page user tried to access, or home
            const from = location.state?.from?.pathname || '/';
            setTimeout(() => navigate(from, { replace: true }), 500);
        }
    };

    const toggleMode = () => {
        setIsRegister(!isRegister);
        setFormErrors({});
        clearError();
        setSuccess('');
    };

    const features = [
        { icon: Brain, text: '37 AI Agents', color: 'text-purple-400' },
        { icon: Shield, text: 'Secure by Design', color: 'text-green-400' },
        { icon: Zap, text: 'Real-time Analytics', color: 'text-yellow-400' },
        { icon: Globe, text: 'OSINT Tools', color: 'text-blue-400' }
    ];

    return (
        <div className="min-h-screen w-full flex bg-gradient-to-br from-gray-900 via-black to-gray-900">
            {/* Left Side - Branding */}
            <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden">
                {/* Animated Background */}
                <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,rgba(6,182,212,0.15),transparent_50%)]"></div>
                <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,rgba(139,92,246,0.15),transparent_50%)]"></div>
                
                {/* Grid Pattern */}
                <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

                {/* Content */}
                <div className="relative z-10 flex flex-col justify-center items-center w-full p-12">
                    {/* Logo */}
                    <div className="mb-8">
                        <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center shadow-2xl shadow-cyan-500/20">
                            <span className="text-4xl font-black text-white">N33</span>
                        </div>
                    </div>

                    {/* Title */}
                    <h1 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 mb-4 text-center">
                        NEXUS33
                    </h1>
                    <p className="text-xl text-gray-400 mb-12 text-center max-w-md">
                        Your AI-Powered Command Center for Life and Work
                    </p>

                    {/* Features */}
                    <div className="grid grid-cols-2 gap-6 w-full max-w-md">
                        {features.map((feature, index) => (
                            <div 
                                key={index}
                                className="flex items-center gap-3 p-4 rounded-xl bg-white/5 backdrop-blur-sm border border-white/10 hover:border-cyan-500/30 transition-all duration-300"
                            >
                                <feature.icon className={`w-6 h-6 ${feature.color}`} />
                                <span className="text-gray-300 text-sm font-medium">{feature.text}</span>
                            </div>
                        ))}
                    </div>

                    {/* Quote */}
                    <div className="mt-12 text-center">
                        <p className="text-gray-500 text-sm italic">
                            "Augment your intelligence. Amplify your potential."
                        </p>
                    </div>
                </div>
            </div>

            {/* Right Side - Form */}
            <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
                <div className="w-full max-w-md">
                    {/* Mobile Logo */}
                    <div className="lg:hidden text-center mb-8">
                        <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-gradient-to-br from-cyan-500 to-purple-600 mb-4">
                            <span className="text-2xl font-black text-white">N33</span>
                        </div>
                        <h1 className="text-3xl font-bold text-white">NEXUS33</h1>
                    </div>

                    {/* Form Card */}
                    <div className="bg-gray-900/80 backdrop-blur-xl rounded-2xl border border-gray-800 p-8 shadow-2xl">
                        {/* Header */}
                        <div className="text-center mb-8">
                            <h2 className="text-2xl font-bold text-white mb-2">
                                {isRegister ? 'Create Account' : 'Welcome Back'}
                            </h2>
                            <p className="text-gray-400">
                                {isRegister 
                                    ? 'Join the future of AI-powered productivity' 
                                    : 'Sign in to your command center'}
                            </p>
                        </div>

                        {/* Success Message */}
                        {success && (
                            <div className="mb-6 p-4 rounded-lg bg-green-500/10 border border-green-500/30 flex items-center gap-3 animate-pulse">
                                <CheckCircle className="w-5 h-5 text-green-400" />
                                <span className="text-green-400 text-sm">{success}</span>
                            </div>
                        )}

                        {/* Error Message */}
                        {error && (
                            <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center gap-3">
                                <AlertCircle className="w-5 h-5 text-red-400" />
                                <span className="text-red-400 text-sm">{error}</span>
                            </div>
                        )}

                        {/* Form */}
                        <form onSubmit={handleSubmit} className="space-y-5">
                            {/* Username (Register only) */}
                            {isRegister && (
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-2">Username</label>
                                    <div className="relative">
                                        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                                        <input
                                            type="text"
                                            name="username"
                                            value={formData.username}
                                            onChange={handleChange}
                                            placeholder="Choose a username"
                                            className={`w-full pl-11 pr-4 py-3 bg-gray-800/50 border ${formErrors.username ? 'border-red-500' : 'border-gray-700'} rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all`}
                                        />
                                    </div>
                                    {formErrors.username && <p className="mt-1 text-xs text-red-400">{formErrors.username}</p>}
                                </div>
                            )}

                            {/* Email */}
                            <div>
                                <label className="block text-sm font-medium text-gray-400 mb-2">Email</label>
                                <div className="relative">
                                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                                    <input
                                        type="email"
                                        name="email"
                                        value={formData.email}
                                        onChange={handleChange}
                                        placeholder="Enter your email"
                                        className={`w-full pl-11 pr-4 py-3 bg-gray-800/50 border ${formErrors.email ? 'border-red-500' : 'border-gray-700'} rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all`}
                                    />
                                </div>
                                {formErrors.email && <p className="mt-1 text-xs text-red-400">{formErrors.email}</p>}
                            </div>

                            {/* Password */}
                            <div>
                                <label className="block text-sm font-medium text-gray-400 mb-2">Password</label>
                                <div className="relative">
                                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        name="password"
                                        value={formData.password}
                                        onChange={handleChange}
                                        placeholder="Enter your password"
                                        className={`w-full pl-11 pr-12 py-3 bg-gray-800/50 border ${formErrors.password ? 'border-red-500' : 'border-gray-700'} rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all`}
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                                    >
                                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                                    </button>
                                </div>
                                {formErrors.password && <p className="mt-1 text-xs text-red-400">{formErrors.password}</p>}
                            </div>

                            {/* Confirm Password (Register only) */}
                            {isRegister && (
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-2">Confirm Password</label>
                                    <div className="relative">
                                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                                        <input
                                            type={showPassword ? 'text' : 'password'}
                                            name="confirmPassword"
                                            value={formData.confirmPassword}
                                            onChange={handleChange}
                                            placeholder="Confirm your password"
                                            className={`w-full pl-11 pr-4 py-3 bg-gray-800/50 border ${formErrors.confirmPassword ? 'border-red-500' : 'border-gray-700'} rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all`}
                                        />
                                    </div>
                                    {formErrors.confirmPassword && <p className="mt-1 text-xs text-red-400">{formErrors.confirmPassword}</p>}
                                </div>
                            )}

                            {/* Submit Button */}
                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-semibold rounded-xl transition-all duration-300 flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {loading ? (
                                    <>
                                        <Loader2 className="w-5 h-5 animate-spin" />
                                        <span>Processing...</span>
                                    </>
                                ) : (
                                    <>
                                        <span>{isRegister ? 'Create Account' : 'Sign In'}</span>
                                        <ArrowRight className="w-5 h-5" />
                                    </>
                                )}
                            </button>
                        </form>

                        {/* Divider */}
                        <div className="flex items-center my-6">
                            <div className="flex-1 h-px bg-gray-800"></div>
                            <span className="px-4 text-sm text-gray-500">or</span>
                            <div className="flex-1 h-px bg-gray-800"></div>
                        </div>

                        {/* Toggle Mode */}
                        <p className="text-center text-gray-400">
                            {isRegister ? 'Already have an account?' : "Don't have an account?"}
                            <button
                                type="button"
                                onClick={toggleMode}
                                className="ml-2 text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
                            >
                                {isRegister ? 'Sign In' : 'Create Account'}
                            </button>
                        </p>

                        {/* Terms */}
                        {isRegister && (
                            <p className="mt-6 text-xs text-gray-500 text-center">
                                By creating an account, you agree to our{' '}
                                <a href="#" className="text-cyan-400 hover:underline">Terms of Service</a>{' '}
                                and{' '}
                                <a href="#" className="text-cyan-400 hover:underline">Privacy Policy</a>
                            </p>
                        )}
                    </div>

                    {/* Footer */}
                    <p className="text-center text-gray-600 text-sm mt-8">
                        © 2024 Nexus33. All rights reserved.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
