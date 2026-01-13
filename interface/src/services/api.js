// ===============================================
// API Service - Authenticated API Calls
// Wraps fetch with automatic JWT token injection
// ===============================================

import { API_URL } from '../config';

/**
 * Get the stored authentication token
 */
const getToken = () => {
    return localStorage.getItem('nexus33_token');
};

/**
 * Make an authenticated API request
 * @param {string} endpoint - API endpoint (without base URL)
 * @param {object} options - Fetch options
 * @returns {Promise<Response>}
 */
const apiRequest = async (endpoint, options = {}) => {
    const token = getToken();
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers,
    });

    // Handle 401 - token expired or invalid
    if (response.status === 401) {
        // Clear token and redirect to login
        localStorage.removeItem('nexus33_token');
        // Optionally dispatch an event to notify the app
        window.dispatchEvent(new CustomEvent('auth:logout'));
    }

    return response;
};

/**
 * GET request with auth
 */
const apiGet = async (endpoint, options = {}) => {
    return apiRequest(endpoint, { ...options, method: 'GET' });
};

/**
 * POST request with auth
 */
const apiPost = async (endpoint, body, options = {}) => {
    return apiRequest(endpoint, {
        ...options,
        method: 'POST',
        body: JSON.stringify(body),
    });
};

/**
 * PUT request with auth
 */
const apiPut = async (endpoint, body, options = {}) => {
    return apiRequest(endpoint, {
        ...options,
        method: 'PUT',
        body: JSON.stringify(body),
    });
};

/**
 * DELETE request with auth
 */
const apiDelete = async (endpoint, options = {}) => {
    return apiRequest(endpoint, { ...options, method: 'DELETE' });
};

export { API_URL, getToken, apiRequest, apiGet, apiPost, apiPut, apiDelete };
export default { API_URL, getToken, apiRequest, apiGet, apiPost, apiPut, apiDelete };
