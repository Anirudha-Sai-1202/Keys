import express from "express";
import {
	logout,
	checkAuth,
	getUserById,
	updateProfile,
} from "../controllers/auth.controller.js";
import { verifyToken } from "../middleware/verifyToken.js";

import passport from "../config/passport.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { config } from "../utils/config.js";

const router = express.Router();

// Auth check (no rate limiting needed for this)
router.get("/check-auth", verifyToken, checkAuth);
router.get("/user/:userId", verifyToken, getUserById);

// Profile endpoints
router.put("/update-profile", verifyToken, updateProfile);

// Logout (no rate limiting for logout)
router.post("/logout", logout);

// ================== SSO ROUTES ==================
// Import SSO utilities
import { checkSSOAuth, exchangeGoogleTokenForSSO } from "../utils/ssoAuth.js";
import { verifyHybridToken } from "../middleware/ssoAuth.js";

// SSO Login - Exchange Google token for SSO token
router.post("/sso/google", async (req, res) => {
	try {
		const { token } = req.body;

		if (!token) {
			return res.status(400).json({
				success: false,
				message: "Google token is required"
			});
		}

		// Exchange Google token with SSO server
		const result = await exchangeGoogleTokenForSSO(
			token,
			req.headers.origin || config.urls.client
		);

		// Forward Set-Cookie headers from auth-server to browser
		// Auth-server sets cookies with domain .vjstartup.com
		if (result.headers && result.headers['set-cookie']) {
			const cookies = result.headers['set-cookie'];
			console.log('📤 Forwarding cookies from auth-server to browser');

			// Set all cookies at once (passing array prevents overwriting)
			res.setHeader('Set-Cookie', cookies);
		}

		res.json({
			success: true,
			token: result.data.token,
			user: result.data.user
		});
	} catch (error) {
		console.error("SSO Google login error:", error);
		res.status(401).json({
			success: false,
			message: error.message || "SSO authentication failed"
		});
	}
});

// SSO Check Auth - Check authentication status with SSO server
router.get("/sso/check-auth", async (req, res) => {
	try {
		const result = await checkSSOAuth(req.cookies);

		if (result.logged_in) {
			res.json({
				success: true,
				user: result.user
			});
		} else {
			res.status(401).json({
				success: false,
				message: "Not authenticated"
			});
		}
	} catch (error) {
		console.error("SSO check auth error:", error);
		res.status(500).json({
			success: false,
			message: "Error checking authentication"
		});
	}
});

// Hybrid check auth - Works with both local and SSO tokens
router.get("/check-auth-hybrid", verifyHybridToken, (req, res) => {
	const user = req.ssoUser || req.user;
	const authMethod = req.authMethod || 'unknown';

	res.json({
		success: true,
		user: user,
		authMethod: authMethod
	});
});

// ================== END SSO ROUTES ==================

// Development only - Clear all users
if (process.env.NODE_ENV === 'development') {
	router.delete("/clear-users", async (req, res) => {
		try {
			const { User } = await import("../models/user.model.js");
			const result = await User.deleteMany({});
			console.log(`🗑️ Cleared ${result.deletedCount} users from database`);
			res.json({
				success: true,
				message: `Cleared ${result.deletedCount} users from database`,
				deletedCount: result.deletedCount
			});
		} catch (error) {
			console.error("Error clearing users:", error);
			res.status(500).json({ success: false, message: "Failed to clear users" });
		}
	});
}

// OAuth routes
router.get("/google",
	passport.authenticate("google", { scope: ["profile", "email"] })
);

// Custom OAuth error handler middleware
const handleOAuthError = (err, req, res, next) => {
	if (err) {
		console.error("❌ OAuth error caught:", err.message);
		const frontendURL = config.urls.client;

		let errorParam = 'auth_failed';

		if (err.message === 'INVALID_EMAIL_DOMAIN') {
			errorParam = 'invalid_domain';
		} else if (err.message === 'USER_NOT_IN_DATABASE') {
			errorParam = 'user_not_registered';
		} else if (err.message === 'GOOGLE_ID_MISMATCH') {
			errorParam = 'google_mismatch';
		}

		const redirectURL = `${frontendURL}/login?error=${errorParam}`;
		console.log("🔗 Redirecting with error:", redirectURL);

		return res.redirect(redirectURL);
	}
	next();
};

router.get("/google/callback",
	(req, res, next) => {
		passport.authenticate("google", { session: false }, (err, user, info) => {
			if (err) {
				// Pass error to the error handler
				return handleOAuthError(err, req, res, next);
			}

			if (!user) {
				// Handle case where user is null
				const error = new Error('USER_NOT_FOUND');
				return handleOAuthError(error, req, res, next);
			}

			// User authenticated successfully - redirect based on role
			try {
				// Generate JWT token for the authenticated user
				const token = generateTokenAndSetCookie(res, user._id, user.role);

				const frontendURL = config.urls.client;

				// Determine redirect URL based on user role
				let redirectURL;
				const userRole = user.role || 'faculty'; // Default to faculty if no role

				if (userRole === 'admin') {
					redirectURL = `${frontendURL}/admin/dashboard?auth=success`;
					console.log("✅ Admin user authenticated - redirecting to admin panel:", redirectURL);
				} else if (userRole === 'security') {
					redirectURL = `${frontendURL}/security/dashboard?auth=success`;
					console.log("✅ Security user authenticated - redirecting to security panel:", redirectURL);
				} else {
					// Default to faculty dashboard for faculty or any other role
					redirectURL = `${frontendURL}/faculty/dashboard?auth=success`;
					console.log("✅ Faculty user authenticated - redirecting to faculty panel:", redirectURL);
				}

				res.redirect(redirectURL);
			} catch (error) {
				console.error("OAuth callback error:", error);
				handleOAuthError(error, req, res, next);
			}
		})(req, res, next);
	}
);

export default router;
