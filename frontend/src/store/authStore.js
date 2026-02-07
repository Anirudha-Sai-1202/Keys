import { create } from "zustand";

import { handleError, handleSuccess } from "../utils/errorHandler.js";
import { config } from "../utils/config.js";

const AUTH_SERVER_URL = import.meta.env.VITE_AUTH_SERVER_URL || "http://localhost:2999";

// Utility to fetch with credentials
const fetchWithCreds = async (url, options = {}) => {
	return fetch(url, {
		...options,
		credentials: "include",
		headers: {
			"Content-Type": "application/json",
			...(options.headers || {})
		}
	});
};
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
			const res = await fetchWithCreds(`${AUTH_SERVER_URL}/logout`, { method: "POST" });
			set({
				user: null,
				isAuthenticated: false,
				error: null,
				isLoading: false,
			});
			handleSuccess("Logged out successfully");
		} catch (error) {
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
			isCheckingAuth: false,
		});
	},

	checkAuth: async () => {
		set({ isCheckingAuth: true, error: null });
		try {
			const res = await fetchWithCreds(`${AUTH_SERVER_URL}/check-auth`, { method: "GET" });
			const data = await res.json();
			if (data.logged_in && data.user) {
				set({
					user: data.user,
					isAuthenticated: true,
					isCheckingAuth: false,
					error: null
				});
			} else {
				set({
					user: null,
					isAuthenticated: false,
					isCheckingAuth: false,
					error: null
				});
			}
		} catch (error) {
			set({
				user: null,
				isAuthenticated: false,
				isCheckingAuth: false,
				error: null
			});
		}
	},

	// Clear error
	clearError: () => set({ error: null }),

	// Clear message
	clearMessage: () => set({ message: null }),

	// Update user profile (example, update as needed for SSO)
	updateProfile: async (profileData) => {
		set({ isLoading: true, error: null });
		try {
			const res = await fetchWithCreds(`${AUTH_SERVER_URL}/update-profile`, {
				method: "PUT",
				body: JSON.stringify(profileData)
			});
			const data = await res.json();
			set({
				user: data.user,
				isLoading: false,
				error: null
			});
			handleSuccess(data.message || "Profile updated successfully!");
			return data;
		} catch (error) {
			set({ error: handleError(error), isLoading: false });
			throw error;
		}
	},
	}));
