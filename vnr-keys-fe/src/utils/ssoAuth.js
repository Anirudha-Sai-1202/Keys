import axios from 'axios';
import { config } from './config.js';

/**
 * SSO Authentication Utilities for Frontend
 * Interacts with the centralized auth server for authentication
 */

/**
 * Login with Google via SSO
 * @param {string} googleToken - Google ID token from Google OAuth
 * @returns {Promise<{success: boolean, token: string, user: object}>}
 */
export const loginWithSSOGoogle = async (googleToken) => {
    const apiUrl = config.api.authUrl;

    if (!apiUrl) {
        throw new Error('API URL not configured');
    }

    try {
        const response = await axios.post(
            `${apiUrl}/sso/google`,
            { token: googleToken },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'x-app-name': config.sso.appName
                },
                withCredentials: true // Important: allow cookies
            }
        );

        return response.data;
    } catch (error) {
        if (error.response) {
            throw new Error(error.response.data.message || 'SSO login failed');
        }
        throw error;
    }
};

/**
 * Check SSO authentication status
 * @returns {Promise<{success: boolean, user?: object}>}
 */
export const checkSSOAuth = async () => {
    const apiUrl = config.api.authUrl;

    if (!apiUrl) {
        throw new Error('API URL not configured');
    }

    try {
        const response = await axios.get(
            `${apiUrl}/sso/check-auth`,
            {
                headers: {
                    'x-app-name': config.sso.appName
                },
                withCredentials: true // Important: send cookies
            }
        );

        return response.data;
    } catch (error) {
        if (error.response?.status === 401) {
            return { success: false, user: null };
        }
        throw error;
    }
};

/**
 * Check authentication with hybrid support (both local and SSO)
 * @returns {Promise<{success: boolean, user?: object, authMethod?: string}>}
 */
export const checkHybridAuth = async () => {
    const apiUrl = config.api.authUrl;

    if (!apiUrl) {
        throw new Error('API URL not configured');
    }

    try {
        const response = await axios.get(
            `${apiUrl}/check-auth-hybrid`,
            {
                headers: {
                    'x-app-name': config.sso.appName
                },
                withCredentials: true
            }
        );

        return response.data;
    } catch (error) {
        if (error.response?.status === 401) {
            return { success: false, user: null };
        }
        throw error;
    }
};

/**
 * Logout from SSO
 * Clears SSO cookies and local storage
 * @returns {Promise<{success: boolean}>}
 */
export const logoutSSO = async () => {
    const ssoServerUrl = config.sso.serverUrl;

    if (!ssoServerUrl) {
        console.warn('SSO server URL not configured 4');
        return { success: false };
    }

    try {
        const response = await axios.post(
            `${ssoServerUrl}/logout`,
            {},
            {
                withCredentials: true
            }
        );

        return response.data;
    } catch (error) {
        console.error('SSO logout error:', error);
        // Even if server logout fails, consider it successful
        return { success: true };
    }
};

/**
 * Get SSO login redirect URL
 * @returns {string|null} SSO Google OAuth URL
 */
export const getSSOLoginUrl = () => {
    const ssoServerUrl = config.sso.serverUrl;

    if (!ssoServerUrl) {
        return null;
    }

    // The auth server uses Google OAuth at /auth/google
    return `${ssoServerUrl}/auth/google`;
};
