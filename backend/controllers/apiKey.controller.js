import { ApiKey } from "../models/apiKey.model.js";
import User from "../models/user.model.js";
import crypto from "crypto";

// Helper function to generate API key
const generateApiKey = (department, keyId) => {
  const prefix = department.toLowerCase();
  const timestamp = Date.now().toString(36);
  const randomBytes = crypto.randomBytes(16).toString('hex');
  return `${prefix}_${keyId}_${timestamp}_${randomBytes}`;
};

// Get all API keys (admin only)
export const getAllApiKeys = async (req, res) => {
  try {
    const apiKeys = await ApiKey.find({ isActive: true })
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      message: "API keys retrieved successfully",
      data: {
        keys: apiKeys,
        total: apiKeys.length
      }
    });
  } catch (error) {
    console.error("Error fetching API keys:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch API keys",
      error: error.message
    });
  }
};

// Get API key statistics (admin only)
export const getApiKeyStats = async (req, res) => {
  try {
    const totalKeys = await ApiKey.countDocuments({ isActive: true });
    const staticKeys = await ApiKey.countDocuments({ isStatic: true, isActive: true });
    const dynamicKeys = await ApiKey.countDocuments({ isStatic: false, isActive: true });
    
    // Get department breakdown
    const departmentStats = await ApiKey.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: "$department", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Get usage statistics
    const usageStats = await ApiKey.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: null,
          totalUsage: { $sum: "$usageCount" },
          avgUsage: { $avg: "$usageCount" },
          maxUsage: { $max: "$usageCount" }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      message: "API key statistics retrieved successfully",
      data: {
        overview: {
          total: totalKeys,
          static: staticKeys,
          dynamic: dynamicKeys
        },
        departments: departmentStats,
        usage: usageStats[0] || { totalUsage: 0, avgUsage: 0, maxUsage: 0 }
      }
    });
  } catch (error) {
    console.error("Error fetching API key statistics:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch API key statistics",
      error: error.message
    });
  }
};

// Get API keys by department
export const getApiKeysByDepartment = async (req, res) => {
  try {
    const { department } = req.params;
    
    const apiKeys = await ApiKey.find({ 
      department: department.toUpperCase(), 
      isActive: true 
    })
    .populate('createdBy', 'name email')
    .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      message: `API keys for ${department} department retrieved successfully`,
      data: {
        keys: apiKeys,
        department: department.toUpperCase(),
        total: apiKeys.length
      }
    });
  } catch (error) {
    console.error("Error fetching API keys by department:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch API keys by department",
      error: error.message
    });
  }
};

// Create new API key (admin only)
export const createApiKey = async (req, res) => {
  try {
    const { keyId, keyName, department, description, permissions, rateLimit } = req.body;

    // Validate required fields
    if (!keyId || !keyName || !department) {
      return res.status(400).json({
        success: false,
        message: "keyId, keyName, and department are required"
      });
    }

    // Check if keyId already exists
    const existingKey = await ApiKey.findOne({ keyId });
    if (existingKey) {
      return res.status(400).json({
        success: false,
        message: "API key with this keyId already exists"
      });
    }

    // Generate unique API key
    const apiKeyValue = generateApiKey(department, keyId);

    // Create new API key
    const newApiKey = new ApiKey({
      keyId,
      keyName,
      apiKey: apiKeyValue,
      department: department.toUpperCase(),
      description: description || "",
      permissions: permissions || { read: true, write: false, delete: false },
      rateLimit: rateLimit || { requestsPerMinute: 100, requestsPerHour: 1000 },
      createdBy: req.user.id,
      isStatic: false
    });

    const savedKey = await newApiKey.save();
    await savedKey.populate('createdBy', 'name email');

    res.status(201).json({
      success: true,
      message: "API key created successfully",
      data: {
        key: savedKey
      }
    });
  } catch (error) {
    console.error("Error creating API key:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create API key",
      error: error.message
    });
  }
};

// Update API key (admin only)
export const updateApiKey = async (req, res) => {
  try {
    const { keyId } = req.params;
    const updates = req.body;

    // Don't allow updating the actual API key value or keyId
    delete updates.apiKey;
    delete updates.keyId;
    delete updates.createdBy;

    const updatedKey = await ApiKey.findOneAndUpdate(
      { keyId, isActive: true },
      updates,
      { new: true, runValidators: true }
    ).populate('createdBy', 'name email');

    if (!updatedKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    res.status(200).json({
      success: true,
      message: "API key updated successfully",
      data: {
        key: updatedKey
      }
    });
  } catch (error) {
    console.error("Error updating API key:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update API key",
      error: error.message
    });
  }
};

// Delete API key (admin only) - only non-static keys can be deleted
export const deleteApiKey = async (req, res) => {
  try {
    const { keyId } = req.params;

    const apiKey = await ApiKey.findOne({ keyId, isActive: true });
    
    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    if (apiKey.isStatic) {
      return res.status(400).json({
        success: false,
        message: "Cannot delete static API keys"
      });
    }

    // Soft delete by setting isActive to false
    apiKey.isActive = false;
    await apiKey.save();

    res.status(200).json({
      success: true,
      message: "API key deleted successfully",
      data: {
        keyId: apiKey.keyId
      }
    });
  } catch (error) {
    console.error("Error deleting API key:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete API key",
      error: error.message
    });
  }
};

// Record API key usage
export const recordApiKeyUsage = async (req, res) => {
  try {
    const { keyId } = req.params;

    const apiKey = await ApiKey.findOne({ keyId, isActive: true });
    
    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    await apiKey.recordUsage();

    res.status(200).json({
      success: true,
      message: "API key usage recorded",
      data: {
        keyId: apiKey.keyId,
        usageCount: apiKey.usageCount,
        lastUsed: apiKey.lastUsed
      }
    });
  } catch (error) {
    console.error("Error recording API key usage:", error);
    res.status(500).json({
      success: false,
      message: "Failed to record API key usage",
      error: error.message
    });
  }
};

// Get single API key by keyId
export const getApiKeyById = async (req, res) => {
  try {
    const { keyId } = req.params;

    const apiKey = await ApiKey.findOne({ keyId, isActive: true })
      .populate('createdBy', 'name email');

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    res.status(200).json({
      success: true,
      message: "API key retrieved successfully",
      data: {
        key: apiKey
      }
    });
  } catch (error) {
    console.error("Error fetching API key:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch API key",
      error: error.message
    });
  }
};
