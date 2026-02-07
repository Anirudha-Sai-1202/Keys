import express from "express";
import {
  getAllApiKeys,
  getApiKeyStats,
  getApiKeysByDepartment,
  createApiKey,
  updateApiKey,
  deleteApiKey,
  recordApiKeyUsage,
  getApiKeyById
} from "../controllers/apiKey.controller.js";
// SSO Auth-server integration: Remove verifyToken middleware. All authentication is handled externally.
import { requireRole } from "../middleware/roleAuth.js";

const router = express.Router();

// All routes require authentication
// SSO Auth-server integration: Remove verifyToken middleware. All authentication is handled externally.

// Get all API keys (admin only)
router.get("/", requireRole("admin"), getAllApiKeys);

// Get API key statistics (admin only)
router.get("/stats", requireRole("admin"), getApiKeyStats);

// Get API keys by department
router.get("/department/:department", getApiKeysByDepartment);

// Get single API key by keyId
router.get("/:keyId", getApiKeyById);

// Create new API key (admin only)
router.post("/", requireRole("admin"), createApiKey);

// Update API key (admin only)
router.put("/:keyId", requireRole("admin"), updateApiKey);

// Delete API key (admin only)
router.delete("/:keyId", requireRole("admin"), deleteApiKey);

// Record API key usage
router.post("/:keyId/usage", recordApiKeyUsage);

export default router;
