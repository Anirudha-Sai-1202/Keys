import User from "../models/user.model.js";

/**
 * Middleware to require specific roles for access
 * @param {...string} allowedRoles - Roles that are allowed to access the route
 * @returns {Function} Express middleware function
 */
export const requireRole = (...allowedRoles) => {
	return async (req, res, next) => {
		try {
			// Ensure user is authenticated (verifyToken should run first)
			if (!req.userId) {
				return res.status(401).json({ 
					success: false, 
					message: "Unauthorized - authentication required" 
				});
			}

			// Get user role from token (set by verifyToken middleware)
			const userRole = req.userRole;

			// If no role in token, fetch from database (fallback)
			if (!userRole) {
				const user = await User.findById(req.userId).select('role');
				if (!user) {
					return res.status(401).json({ 
						success: false, 
						message: "Unauthorized - user not found" 
					});
				}
				req.userRole = user.role;
			}

			// Check if user's role is in the allowed roles
			if (!allowedRoles.includes(req.userRole)) {
				return res.status(403).json({ 
					success: false, 
					message: `Forbidden - requires one of the following roles: ${allowedRoles.join(', ')}` 
				});
			}

			next();
		} catch (error) {
			console.error("Error in requireRole middleware:", error);
			return res.status(500).json({ 
				success: false, 
				message: "Server error during role verification" 
			});
		}
	};
};

/**
 * Predefined role combinations for common use cases
 */
export const rolePermissions = {
	// Admin only
	adminOnly: requireRole('admin'),
	
	// Admin and Security
	adminOrSecurity: requireRole('admin', 'security'),
	
	// Admin and Faculty
	adminOrFaculty: requireRole('admin', 'faculty'),

	// Admin, Security, and Faculty (for collective operations)
	adminOrSecurityOrFaculty: requireRole('admin', 'security', 'faculty'),

	// All roles (authenticated users)
	anyRole: requireRole('admin', 'faculty', 'security'),
	
	// Faculty only
	facultyOnly: requireRole('faculty'),
	
	// Security only
	securityOnly: requireRole('security')
};
