import express from "express";
import { verifyToken } from "../middleware/verifyToken.js";
import { rolePermissions } from "../middleware/roleAuth.js";
import { asyncHandler } from "../utils/errorHandler.js";
import AuditService from "../services/auditService.js";

const router = express.Router();

// All audit routes require authentication
router.use(verifyToken);

/**
 * Get audit logs with optional filters
 */
router.get("/", rolePermissions.adminOrSecurityOrFaculty, asyncHandler(async (req, res) => {
  const {
    action,
    performedBy,
    keyNumber,
    dateFrom,
    dateTo,
    limit = 100
  } = req.query;

  const filters = {};
  if (action) filters.action = action;
  if (performedBy) filters.performedBy = performedBy;
  if (keyNumber) filters.keyNumber = keyNumber;
  if (dateFrom) filters.dateFrom = dateFrom;
  if (dateTo) filters.dateTo = dateTo;

  const auditLogs = await AuditService.getAuditLogs(filters, parseInt(limit));

  res.status(200).json({
    success: true,
    message: "Audit logs retrieved successfully",
    data: {
      logs: auditLogs,
      total: auditLogs.length,
      filters: filters
    },
  });
}));

/**
 * Get collective return logs
 */
router.get("/collective-returns", rolePermissions.adminOrSecurityOrFaculty, asyncHandler(async (req, res) => {
  const { limit = 100 } = req.query;

  const collectiveReturnLogs = await AuditService.getCollectiveReturnLogs(parseInt(limit));

  res.status(200).json({
    success: true,
    message: "Collective return logs retrieved successfully",
    data: {
      logs: collectiveReturnLogs,
      total: collectiveReturnLogs.length,
    },
  });
}));

/**
 * Get audit logs for a specific key
 */
router.get("/key/:keyId", rolePermissions.adminOrSecurityOrFaculty, asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const { limit = 50 } = req.query;

  const keyAuditLogs = await AuditService.getKeyAuditLogs(keyId, parseInt(limit));

  res.status(200).json({
    success: true,
    message: "Key audit logs retrieved successfully",
    data: {
      logs: keyAuditLogs,
      total: keyAuditLogs.length,
      keyId: keyId
    },
  });
}));

/**
 * Get audit logs for a specific user
 */
router.get("/user/:userId", rolePermissions.adminOrSecurityOrFaculty, asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { limit = 50 } = req.query;

  // Users can only view their own audit logs unless they are admin/security
  if (req.userRole !== 'admin' && req.userRole !== 'security' && req.userId !== userId) {
    return res.status(403).json({
      success: false,
      message: "You can only view your own audit logs"
    });
  }

  const userAuditLogs = await AuditService.getUserAuditLogs(userId, parseInt(limit));

  res.status(200).json({
    success: true,
    message: "User audit logs retrieved successfully",
    data: {
      logs: userAuditLogs,
      total: userAuditLogs.length,
      userId: userId
    },
  });
}));

export default router;
