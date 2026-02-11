import { create } from "zustand";
import axios from "axios";
import { handleError, handleSuccess } from "../utils/errorHandler.js";
import { config } from "../utils/config.js";
import { loginWithSSOGoogle, checkSSOAuth, checkHybridAuth, logoutSSO } from "../utils/ssoAuth.js";

const API_URL = config.api.authUrl;

// Configure axios defaults
axios.defaults.withCredentials = true;

// Axios will automatically send cookies with withCredentials: true
// No need to manually add Authorization header for SSO authentication

// Add response interceptor to handle auth errors
axios.interceptors.response.use(
	(response) => response,
	async (error) => {
		if (error.response?.status === 401) {
			// SSO cookie invalid/expired - user will be redirected to login
			console.log('❌ Authentication failed - SSO cookie invalid');
		}
		return Promise.reject(error);
	}
);

export const useAuthStore = create((set, get) => ({
	user: null,
	isAuthenticated: false,
	error: null,
	isLoading: false,
	isCheckingAuth: false,
	message: null,
	getRoleBasedRoute: () => {
		const { user } = get();
		if (!user || !user.role) return '/dashboard';

		switch (user.role) {
			case 'admin':
				return '/dashboard/admin';
			case 'faculty':
				return '/dashboard/faculty';
			case 'security':
				return '/dashboard/security';
			default:
				return '/dashboard';
		}
	},

	// Check if user has required role
	hasRole: (requiredRole) => {
		const { user } = get();
		if (!user || !user.role) return false;

		// Admin has access to all roles
		if (user.role === 'admin') return true;

		// Check specific role
		return user.role === requiredRole;
	},

	// Check if user has any of the required roles
	hasAnyRole: (requiredRoles) => {
		const { user } = get();
		if (!user || !user.role) return false;

		// Admin has access to all roles
		if (user.role === 'admin') return true;

		// Check if user role is in required roles
		return requiredRoles.includes(user.role);
	},

	logout: async () => {
		set({ isLoading: true, error: null });
		try {
			await axios.post(`${API_URL}/logout`);

			set({
				user: null,
				isAuthenticated: false,
				error: null,
				isLoading: false,
			});

			handleSuccess("Logged out successfully");
		} catch (error) {
			// Even if logout fails on server, clear local state
			set({
				user: null,
				isAuthenticated: false,
				error: null,
				isLoading: false,
			});
		}
	},

	// Force reset auth state if stuck
	forceResetAuthState: () => {
		console.log('🔄 Force resetting auth state...');
		set({
			_isCheckingAuthInProgress: false,
			isCheckingAuth: false
		});
	},

	// Check authentication status using SSO
	checkAuth: async () => {
		// Prevent double-checking
		// const state = get();
		// if (state._isCheckingAuthInProgress) {
		//	console.log('⚠️ Auth check already in progress, skipping...');
		//	return;
		// }

		console.log('🔄 Starting SSO auth check...');
		set({ isCheckingAuth: true, error: null, _isCheckingAuthInProgress: true });

		// Safety timeout to reset flag in case something goes wrong
		const timeoutId = setTimeout(() => {
			console.log('⏰ Auth check timeout, resetting flag...');
			set({ _isCheckingAuthInProgress: false, isCheckingAuth: false });
		}, 5000); // 5 second timeout

		try {
			console.log('=== FRONTEND CHECK AUTH (SSO) ===');
			console.log('Making request to:', `${API_URL}/check-auth`);
			console.log('Axios withCredentials:', axios.defaults.withCredentials);

			const response = await axios.get(`${API_URL}/check-auth`);

			console.log('✅ Check auth successful:', response.data);
			console.log('===========================');

			clearTimeout(timeoutId);
			set({
				user: response.data.user,
				isAuthenticated: true,
				isCheckingAuth: false,
				error: null,
				_isCheckingAuthInProgress: false
			});
		} catch (error) {
			console.log('=== CHECK AUTH FAILED ===');
			console.log('Error:', error.response?.data || error.message);
			console.log('Status:', error.response?.status);
			console.log('=========================');

			clearTimeout(timeoutId);
			// Don't show error toast for auth check failures
			set({
				user: null,
				isAuthenticated: false,
				isCheckingAuth: false,
				error: null,
				_isCheckingAuthInProgress: false
			});
		}
	},

	// Clear error
	clearError: () => set({ error: null }),

	// Clear message
	clearMessage: () => set({ message: null }),

	// Update user profile
	updateProfile: async (profileData) => {
		set({ isLoading: true, error: null });

		try {
			const response = await axios.put(`${API_URL}/update-profile`, profileData);

			set({
				user: response.data.user,
				isLoading: false,
				error: null
			});

			handleSuccess(response.data.message || "Profile updated successfully!");
			return response.data;
		} catch (error) {
			const errorMessage = handleError(error);
			set({ error: errorMessage, isLoading: false });
			throw error;
		}
	},

	// ================== SSO METHODS ==================

	/**
	 * Login with Google via SSO
	 * @param {string} googleToken - Google ID token
	 */
	loginWithSSO: async (googleToken) => {
		set({ isLoading: true, error: null });
		try {
			console.log('🔐 SSO Login: Exchanging Google token...');

			// Step 1: Send Google token to backend which exchanges with auth-server
			const response = await axios.post(`${API_URL}/sso/google`,
				{ token: googleToken },
				{ withCredentials: true }
			);

			if (!response.data.success) {
				throw new Error(response.data.message || 'SSO authentication failed');
			}

			console.log('✅ SSO token exchanged, fetching user data...');

			// Step 2: Now fetch full user data from our backend using the cookie
			const userResponse = await axios.get(`${API_URL}/check-auth`, {
				withCredentials: true
			});

			if (userResponse.data.success && userResponse.data.user) {
				// Successfully got user data
				set({
					user: userResponse.data.user,
					isAuthenticated: true,
					error: null,
					isLoading: false,
				});

				console.log('✅ User data fetched successfully:', userResponse.data.user);
				return userResponse.data.user;
			}

			throw new Error('Failed to fetch user data after SSO login');
		} catch (error) {
			console.error('❌ SSO Login error:', error);

			// Handle different error scenarios with specific messages
			let errorMessage = "Authentication failed";

			if (error.response?.status === 401) {
				// User not found in database
				errorMessage = "Access Denied: This application is only for registered faculty members.";
			} else if (error.response?.status === 403) {
				// Invalid credentials or college email required
				errorMessage = "Login failed. Please use your college email (@vnrvjiet.in only)";
			} else if (error.response?.data?.message) {
				errorMessage = error.response.data.message;
			} else if (error.message) {
				errorMessage = error.message;
			}

			set({
				error: errorMessage,
				isLoading: false,
				isAuthenticated: false,
				user: null,
			});

			throw new Error(errorMessage);
		}
	},

	/**
	 * Check authentication using SSO
	 */
	checkSSOAuthStatus: async () => {
		set({ isCheckingAuth: true, error: null });

		try {
			console.log('🔍 Checking SSO auth status...');

			const result = await checkSSOAuth();

			if (result.success && result.user) {
				set({
					user: result.user,
					isAuthenticated: true,
					isCheckingAuth: false,
					error: null
				});

				console.log('✅ SSO Auth check successful:', result.user);
				return true;
			} else {
				set({
					user: null,
					isAuthenticated: false,
					isCheckingAuth: false,
					error: null
				});
				return false;
			}
		} catch (error) {
			console.error('❌ SSO Auth check error:', error);
			set({
				user: null,
				isAuthenticated: false,
				isCheckingAuth: false,
				error: null
			});
			return false;
		}
	},

	/**
	 * Check authentication with hybrid support (SSO + local)
	 */
	checkHybridAuthStatus: async () => {
		set({ isCheckingAuth: true, error: null });

		try {
			console.log('🔍 Checking hybrid auth status (SSO + Local)...');

			const result = await checkHybridAuth();

			if (result.success && result.user) {
				set({
					user: result.user,
					isAuthenticated: true,
					isCheckingAuth: false,
					error: null
				});

				console.log(`✅ Hybrid auth check successful (${result.authMethod}):`, result.user);
				return true;
			} else {
				set({
					user: null,
					isAuthenticated: false,
					isCheckingAuth: false,
					error: null
				});
				return false;
			}
		} catch (error) {
			console.error('❌ Hybrid auth check error:', error);
			set({
				user: null,
				isAuthenticated: false,
				isCheckingAuth: false,
				error: null
			});
			return false;
		}
	},

	/**
	 * SSO Logout - auth-server clears cookies
	 */
	logoutWithSSO: async () => {
		set({ isLoading: true, error: null });

		console.log('🚪 Logging out via auth-server...');

		// Auth-server clears all cookies
		await logoutSSO();

		// Clear local state
		set({
			user: null,
			isAuthenticated: false,
			error: null,
			isLoading: false,
		});

		// Redirect to login
		window.location.href = '/login';
	},
}));
