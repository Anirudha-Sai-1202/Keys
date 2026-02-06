import { AuditLog } from "../models/auditLog.model.js";

/**
 * Audit Service for logging key operations
 */
class AuditService {
  /**
   * Extract request metadata for audit logging
   * @param {Object} req - Express request object
   * @returns {Object} Metadata object
   */
  static extractRequestMetadata(req) {
    return {
      ipAddress: req.ip || req.connection?.remoteAddress,
      userAgent: req.get('User-Agent'),
      sessionId: req.sessionID,
    };
  }

  /**
   * Log key taken operation
   * @param {Object} key - Key object
   * @param {Object} user - User who took the key
   * @param {Object} req - Express request object
   * @param {Object} additionalMetadata - Additional metadata
   */
  static async logKeyTaken(key, user, req, additionalMetadata = {}) {
    const metadata = {
      ...this.extractRequestMetadata(req),
      ...additionalMetadata,
    };

    return await AuditLog.logKeyOperation(
      "key_taken",
      key,
      user,
      null,
      metadata
    );
  }

  /**
   * Log key returned operation
   * @param {Object} key - Key object
   * @param {Object} returnedBy - User who returned the key
   * @param {Object} req - Express request object
   * @param {Object} originalUser - Original user who had the key (for collective returns)
   * @param {Object} additionalMetadata - Additional metadata
   */
  static async logKeyReturned(key, returnedBy, req, originalUser = null, additionalMetadata = {}) {
    const metadata = {
      ...this.extractRequestMetadata(req),
      ...additionalMetadata,
      isBatchReturn: additionalMetadata.isBatch || false
    };

    return await AuditLog.logKeyOperation(
      "key_returned",
      key,
      returnedBy,
      originalUser,
      metadata
    );
  }

  /**
   * Log QR scan request operation
   * @param {Object} key - Key object
   * @param {Object} scannedBy - User who scanned the QR
   * @param {Object} requestedBy - User who requested the key
   * @param {Object} req - Express request object
   * @param {string} qrCodeId - QR code identifier
   */
  static async logQRScanRequest(key, scannedBy, requestedBy, req, qrCodeId) {
    const metadata = {
      ...this.extractRequestMetadata(req),
      qrCodeId,
    };

    return await AuditLog.logKeyOperation(
      "qr_scan_request",
      key,
      scannedBy,
      requestedBy,
      metadata
    );
  }

  /**
   * Log QR scan return operation
   * @param {Object} key - Key object
   * @param {Object} scannedBy - User who scanned the QR
   * @param {Object} originalUser - User who originally had the key
   * @param {Object} req - Express request object
   * @param {string} qrCodeId - QR code identifier
   */
  static async logQRScanReturn(key, scannedBy, originalUser, req, qrCodeId) {
    const metadata = {
      ...this.extractRequestMetadata(req),
      qrCodeId,
      isCollectiveReturn: scannedBy._id.toString() !== originalUser._id.toString(),
    };

    const action = metadata.isCollectiveReturn ? "key_collective_return" : "qr_scan_return";

    return await AuditLog.logKeyOperation(
      action,
      key,
      scannedBy,
      originalUser,
      metadata
    );
  }

  /**
   * Log manual collection operation
   * @param {Object} key - Key object
   * @param {Object} collectedBy - User who manually collected the key
   * @param {Object} originalUser - User who originally had the key
   * @param {Object} req - Express request object
   * @param {string} reason - Reason for manual collection
   */
  static async logManualCollection(key, collectedBy, originalUser, req, reason = null) {
    const metadata = {
      ...this.extractRequestMetadata(req),
      reason,
      isCollectiveReturn: collectedBy._id.toString() !== originalUser._id.toString(),
    };

    const action = metadata.isCollectiveReturn ? "key_collective_return" : "manual_collection";

    return await AuditLog.logKeyOperation(
      action,
      key,
      collectedBy,
      originalUser,
      metadata
    );
  }

  /**
   * Log key creation operation
   * @param {Object} key - Key object
   * @param {Object} createdBy - User who created the key
   * @param {Object} req - Express request object
   */
  static async logKeyCreated(key, createdBy, req) {
    const metadata = this.extractRequestMetadata(req);

    return await AuditLog.logKeyOperation(
      "key_created",
      key,
      createdBy,
      null,
      metadata
    );
  }

  /**
   * Log key update operation
   * @param {Object} key - Key object
   * @param {Object} updatedBy - User who updated the key
   * @param {Object} req - Express request object
   * @param {Object} changes - Changes made to the key
   */
  static async logKeyUpdated(key, updatedBy, req, changes = {}) {
    const metadata = {
      ...this.extractRequestMetadata(req),
      changes,
    };

    return await AuditLog.logKeyOperation(
      "key_updated",
      key,
      updatedBy,
      null,
      metadata
    );
  }

  /**
   * Log key deletion operation
   * @param {Object} key - Key object
   * @param {Object} deletedBy - User who deleted the key
   * @param {Object} req - Express request object
   */
  static async logKeyDeleted(key, deletedBy, req) {
    const metadata = this.extractRequestMetadata(req);

    return await AuditLog.logKeyOperation(
      "key_deleted",
      key,
      deletedBy,
      null,
      metadata
    );
  }

  /**
   * Get audit logs with filters
   * @param {Object} filters - Filter criteria
   * @param {number} limit - Maximum number of logs to return
   * @returns {Promise<Array>} Array of audit logs
   */
  static async getAuditLogs(filters = {}, limit = 100) {
    return await AuditLog.getAuditLogs(filters, limit);
  }

  /**
   * Get collective return logs
   * @param {number} limit - Maximum number of logs to return
   * @returns {Promise<Array>} Array of collective return logs
   */
  static async getCollectiveReturnLogs(limit = 100) {
    return await AuditLog.getCollectiveReturnLogs(limit);
  }

  /**
   * Get audit logs for a specific key
   * @param {string} keyId - Key ID
   * @param {number} limit - Maximum number of logs to return
   * @returns {Promise<Array>} Array of audit logs for the key
   */
  static async getKeyAuditLogs(keyId, limit = 50) {
    return await AuditLog.getKeyAuditLogs(keyId, limit);
  }

  /**
   * Get audit logs for a specific user
   * @param {string} userId - User ID
   * @param {number} limit - Maximum number of logs to return
   * @returns {Promise<Array>} Array of audit logs for the user
   */
  static async getUserAuditLogs(userId, limit = 50) {
    return await AuditLog.getUserAuditLogs(userId, limit);
  }
}

export default AuditService;
