import axios from 'axios';
import { config } from './config.js';

/**
 * SSO Utilities for interacting with the centralized auth server
 */

/**
 * Verify a token with the SSO auth server
 * @param {string} token - JWT token to verify
 * @returns {Promise<{valid: boolean, user?: object}>}
 */
export const verifySSOToken = async (token) => {
    const ssoServerUrl = config.auth.ssoServerUrl;

    if (!ssoServerUrl) {
        throw new Error('SSO server URL not configured 1');
    }

    try {
        const response = await axios.post(
            `${ssoServerUrl}/verify-token`,
            { token },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'x-app-name': config.auth.appName
                },
                timeout: 5000 // 5 second timeout
            }
        );

        return response.data;
    } catch (error) {
        if (error.response) {
            // Server responded with error
            return { valid: false, error: error.response.data };
        }
        // Network or other error
        throw error;
    }
};

/**
 * Check authentication status with SSO server using cookies
 * @param {object} cookies - Request cookies
 * @returns {Promise<{logged_in: boolean, user?: object}>}
 */
export const checkSSOAuth = async (cookies) => {
    const ssoServerUrl = config.auth.ssoServerUrl;

    if (!ssoServerUrl) {
        throw new Error('SSO server URL not configured 2');
    }

    try {
        const response = await axios.get(
            `${ssoServerUrl}/check-auth`,
            {
                headers: {
                    'Cookie': Object.entries(cookies)
                        .map(([key, value]) => `${key}=${value}`)
                        .join('; '),
                    'x-app-name': config.auth.appName
                },
                timeout: 5000
            }
        );

        return response.data;
    } catch (error) {
        if (error.response) {
            return { logged_in: false };
        }
        throw error;
    }
};

/**
 * Exchange Google token for SSO token
 * @param {string} googleToken - Google ID token
 * @param {string} origin - Request origin for app detection
 * @returns {Promise<{token: string, user: object}>}
 */
export const exchangeGoogleTokenForSSO = async (googleToken, origin) => {
    const ssoServerUrl = "http://localhost:2999";

    if (!ssoServerUrl) {
        throw new Error('SSO server URL not configured 3');
    }

    try {
        const response = await axios.post(
            `${ssoServerUrl}/auth/google`,
            {
                token: googleToken,
                app: config.auth.appName
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Origin': origin,
                    'x-app-name': config.auth.appName
                },
                timeout: 10000
            }
        );

        return response.data;
    } catch (error) {
        if (error.response) {
            throw new Error(error.response.data.error || 'SSO authentication failed');
        }
        throw error;
    }
};

/**
 * Get SSO login URL
 * @returns {string} SSO login URL
 */
export const getSSOLoginUrl = () => {
    const ssoServerUrl = config.auth.ssoServerUrl;

    if (!ssoServerUrl) {
        return null;
    }

    // Auth server uses Google OAuth, so we can construct the URL
    return `${ssoServerUrl}/auth/google`;
};
