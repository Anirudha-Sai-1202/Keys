import express from "express";
import {
	getAdminDashboard,
	getFacultyDashboard,
	getSecurityDashboard,
	getUserProfile,
	getAllUsers,
	createUser,
	updateUser,
	deleteUser,
	toggleUserVerification,
	getSecuritySettings,
	updateSecuritySettings,
	getSystemReports,
	getKeyUsageAnalytics,
	getActiveUsersAnalytics,
	getPeakUsageAnalytics
} from "../controllers/dashboard.controller.js";
// SSO Auth-server integration: Remove verifyToken middleware. All authentication is handled externally.
import { rolePermissions } from "../middleware/roleAuth.js";

const router = express.Router();

// All dashboard routes require authentication
// SSO Auth-server integration: Remove verifyToken middleware. All authentication is handled externally.

// Role-specific dashboard endpoints
router.get("/admin", rolePermissions.adminOnly, getAdminDashboard);
router.get("/faculty", rolePermissions.adminOrFaculty, getFacultyDashboard);
router.get("/security", rolePermissions.adminOrSecurity, getSecurityDashboard);

// Admin-only user management endpoints
router.get("/users", rolePermissions.adminOnly, getAllUsers);
router.post("/users", rolePermissions.adminOnly, createUser);
router.put("/users/:userId", rolePermissions.adminOnly, updateUser);
router.delete("/users/:userId", rolePermissions.adminOnly, deleteUser);
router.patch("/users/:userId/verify", rolePermissions.adminOnly, toggleUserVerification);

// Admin-only security settings endpoints
router.get("/security-settings", rolePermissions.adminOnly, getSecuritySettings);
router.put("/security-settings", rolePermissions.adminOnly, updateSecuritySettings);

// Admin-only reports endpoints
router.get("/reports", rolePermissions.adminOnly, getSystemReports);

// Admin-only analytics endpoints
router.get("/analytics/key-usage", rolePermissions.adminOnly, getKeyUsageAnalytics);
router.get("/analytics/active-users", rolePermissions.adminOnly, getActiveUsersAnalytics);
router.get("/analytics/peak-usage", rolePermissions.adminOnly, getPeakUsageAnalytics);

// General user profile endpoint (accessible to all authenticated users)
router.get("/profile", getUserProfile);

export default router;
