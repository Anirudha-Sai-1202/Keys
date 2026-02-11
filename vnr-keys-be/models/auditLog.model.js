import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      enum: [
        "key_taken",
        "key_returned", 
        "batch-return",
        "key_collective_return",
        "key_created",
        "key_updated",
        "key_deleted",
        "qr_scan_request",
        "qr_scan_return",
        "manual_collection"
      ],
    },
    entityType: {
      type: String,
      required: true,
      enum: ["key", "user"],
      default: "key",
    },
    entityId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      refPath: "entityType",
    },
    // User who performed the action
    performedBy: {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      name: {
        type: String,
        required: true,
      },
      email: {
        type: String,
        required: true,
      },
      role: {
        type: String,
        required: true,
        enum: ["faculty", "security", "admin"],
      },
    },
    originalUser: {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null,
      },
      name: {
        type: String,
        default: null,
      },
      email: {
        type: String,
        default: null,
      },
    },
    // Key details at the time of action
    keyDetails: {
      keyNumber: {
        type: String,
        required: true,
      },
      keyName: {
        type: String,
        required: true,
      },
      location: {
        type: String,
        required: true,
      },
      department: {
        type: String,
        default: null,
      },
      block: {
        type: String,
        default: null,
      },
    },
    // Additional context
    metadata: {
      ipAddress: {
        type: String,
        default: null,
      },
      userAgent: {
        type: String,
        default: null,
      },
      sessionId: {
        type: String,
        default: null,
      },
      // For QR operations
      qrCodeId: {
        type: String,
        default: null,
      },
      // For collective returns
      isCollectiveReturn: {
        type: Boolean,
        default: false,
      },
      reason: {
        type: String,
        default: null,
      },
    },
    // Status tracking
    status: {
      type: String,
      enum: ["success", "failed", "pending"],
      default: "success",
    },
    errorMessage: {
      type: String,
      default: null,
    },
  },
  { 
    timestamps: true,
    collection: "auditlogs"
  }
);

// Indexes for better performance
auditLogSchema.index({ action: 1 });
auditLogSchema.index({ "performedBy.userId": 1 });
auditLogSchema.index({ "originalUser.userId": 1 });
auditLogSchema.index({ entityId: 1 });
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ "keyDetails.keyNumber": 1 });
auditLogSchema.index({ "metadata.isCollectiveReturn": 1 });

// Static method to log key operations
auditLogSchema.statics.logKeyOperation = async function(
  action,
  key,
  performedBy,
  originalUser = null,
  metadata = {}
) {
  try {
    const auditLog = new this({
      action,
      entityType: "key",
      entityId: key._id,
      performedBy: {
        userId: performedBy._id,
        name: performedBy.name,
        email: performedBy.email,
        role: performedBy.role,
      },
      originalUser: originalUser ? {
        userId: originalUser._id,
        name: originalUser.name,
        email: originalUser.email,
      } : null,
      keyDetails: {
        keyNumber: key.keyNumber,
        keyName: key.keyName,
        location: key.location,
        department: key.department,
        block: key.block,
      },
      metadata: {
        ...metadata,
        isCollectiveReturn: action === "key_collective_return",
      },
    });

    await auditLog.save();
    return auditLog;
  } catch (error) {
    console.error("Error creating audit log:", error);
    // Don't throw error to avoid breaking the main operation
    return null;
  }
};

// Static method to get audit logs for a key
auditLogSchema.statics.getKeyAuditLogs = function(keyId, limit = 50) {
  return this.find({ entityId: keyId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate("performedBy.userId", "name email role")
    .populate("originalUser.userId", "name email");
};

// Static method to get audit logs for a user
auditLogSchema.statics.getUserAuditLogs = function(userId, limit = 50) {
  return this.find({
    $or: [
      { "performedBy.userId": userId },
      { "originalUser.userId": userId }
    ]
  })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate("performedBy.userId", "name email role")
    .populate("originalUser.userId", "name email");
};

// Static method to get collective return logs
auditLogSchema.statics.getCollectiveReturnLogs = function(limit = 100) {
  return this.find({ "metadata.isCollectiveReturn": true })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate("performedBy.userId", "name email role")
    .populate("originalUser.userId", "name email");
};

// Static method to get recent audit logs with filters
auditLogSchema.statics.getAuditLogs = function(filters = {}, limit = 100) {
  const query = {};

  if (filters.action) {
    query.action = filters.action;
  }

  if (filters.performedBy) {
    query["performedBy.userId"] = filters.performedBy;
  }

  if (filters.keyNumber) {
    query["keyDetails.keyNumber"] = new RegExp(filters.keyNumber, 'i');
  }

  if (filters.dateFrom || filters.dateTo) {
    query.createdAt = {};
    if (filters.dateFrom) {
      query.createdAt.$gte = new Date(filters.dateFrom);
    }
    if (filters.dateTo) {
      query.createdAt.$lte = new Date(filters.dateTo);
    }
  }

  return this.find(query)
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate("performedBy.userId", "name email role")
    .populate("originalUser.userId", "name email");
};

export const AuditLog = mongoose.model("AuditLog", auditLogSchema);
