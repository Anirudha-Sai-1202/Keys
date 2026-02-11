import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const verifyToken = async (req, res, next) => {
	// Try to get token from SSO cookie (userToken) first, then legacy token, then Authorization header
	let token = req.cookies.userToken || req.cookies.token;

	// If no cookie token, check Authorization header
	if (!token) {
		const authHeader = req.headers.authorization;
		if (authHeader && authHeader.startsWith('Bearer ')) {
			token = authHeader.substring(7);
		}
	}

	// Log token verification attempts for debugging
	console.log(`[${req.method}] ${req.url} - Token: ${token ? 'Present' : 'Missing'}`);
	console.log('Cookies:', Object.keys(req.cookies));
	console.log('Auth header:', req.headers.authorization ? 'Present' : 'Missing');

	if (!token) {
		console.log('❌ No token found in cookies or Authorization header');
		return res.status(401).json({ success: false, message: "Unauthorized - no token provided" });
	}

	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);

		if (!decoded) {
			console.log('❌ Token decoded but empty');
			return res.status(401).json({ success: false, message: "Unauthorized - invalid token" });
		}

		console.log('🔍 Decoded token:', decoded);

		// Handle SSO token (has email) vs legacy token (has userId)
		if (decoded.email) {
			// SSO token - fetch user from database by email
			console.log('🔐 SSO token detected - looking up user by email:', decoded.email);

			try {
				const user = await User.findOne({ email: decoded.email }).select('_id role name email');

				if (!user) {
					console.log('❌ User not found in database:', decoded.email);
					return res.status(401).json({ success: false, message: "User not found" });
				}

				req.userId = user._id.toString();
				req.userRole = user.role;
				req.ssoUser = decoded; // Keep SSO user data
				console.log(`✅ SSO Token verified for user: ${user.email} (${user.role})`);
			} catch (dbError) {
				console.log('❌ Database error:', dbError.message);
				return res.status(500).json({ success: false, message: "Database error" });
			}
		} else if (decoded.userId) {
			// Legacy local token
			console.log('🔑 Legacy token detected - using userId:', decoded.userId);

			req.userId = decoded.userId;
			req.userRole = decoded.role;

			// Check if the role in the token matches the current role in the database
			try {
				const user = await User.findById(decoded.userId).select('role');
				if (user && user.role !== decoded.role) {
					console.log(`🔄 Role mismatch detected - Token: ${decoded.role}, Database: ${user.role}`);
					req.userRole = user.role; // Use the current role from database
				}
			} catch (dbError) {
				console.log('⚠️ Warning: Could not verify role from database:', dbError.message);
				// Continue with token role if database check fails
			}

			console.log(`✅ Legacy token verified for user: ${decoded.userId} (${req.userRole})`);
		} else {
			console.log('❌ Invalid token structure - missing email and userId');
			return res.status(401).json({ success: false, message: "Invalid token structure" });
		}

		next();
	} catch (error) {
		console.log("❌ Token verification error:", error.message);
		return res.status(500).json({ success: false, message: "Server error" });
	}
};
