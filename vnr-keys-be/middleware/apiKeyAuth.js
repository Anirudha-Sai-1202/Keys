import { ApiKey } from "../models/apiKey.model.js";
import User from "../models/user.model.js";

/**
 * Middleware to check API key access permissions
 * Admin users have access to all API keys across all departments
 * Other users may have restricted access based on future requirements
 */

export const checkApiKeyAccess = async (req, res, next) => {
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

    // Admin users have access to all API keys
    if (userRole === 'admin') {
      req.hasFullApiKeyAccess = true;
      req.accessibleDepartments = ["CSE", "EEE", "AIML", "IoT", "ECE", "MECH", "CIVIL", "IT", "ADMIN", "RESEARCH"];
      return next();
    }

    // For future implementation: other roles may have department-specific access
    // For now, we'll allow all authenticated users to view API keys
    req.hasFullApiKeyAccess = false;
    req.accessibleDepartments = []; // Can be expanded based on user's department

    next();
  } catch (error) {
    console.error("Error in checkApiKeyAccess middleware:", error);
    return res.status(500).json({ 
      success: false, 
      message: "Server error during API key access verification" 
    });
  }
};

/**
 * Middleware to validate API key ownership or admin access
 * Used for operations that modify specific API keys
 */
export const validateApiKeyOwnership = async (req, res, next) => {
  try {
    const { keyId } = req.params;
    const userRole = req.userRole;
    const userId = req.userId;

    // Find the API key
    const apiKey = await ApiKey.findById(keyId);
    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    // Admin users can access any API key
    if (userRole === 'admin') {
      req.apiKey = apiKey;
      return next();
    }

    // For other users, check if they created the key or have department access
    // This can be expanded based on future requirements
    if (apiKey.createdBy && apiKey.createdBy.toString() === userId) {
      req.apiKey = apiKey;
      return next();
    }

    return res.status(403).json({
      success: false,
      message: "Access denied - insufficient permissions to access this API key"
    });

  } catch (error) {
    console.error("Error in validateApiKeyOwnership middleware:", error);
    return res.status(500).json({ 
      success: false, 
      message: "Server error during API key ownership validation" 
    });
  }
};

/**
 * Middleware to filter API keys based on user access level
 * Admin sees all keys, others see only their accessible keys
 */
export const filterApiKeysByAccess = (req, res, next) => {
  // Add filter conditions based on user role
  if (req.userRole === 'admin') {
    // Admin can see all keys - no additional filtering needed
    req.apiKeyFilter = {};
  } else {
    // For other users, add department-based filtering if needed
    // This can be expanded based on future requirements
    req.apiKeyFilter = {
      // Example: department: { $in: req.accessibleDepartments }
    };
  }

  next();
};

/**
 * Helper function to check if user can perform specific actions on API keys
 */
export const canPerformApiKeyAction = (userRole, action, apiKey = null) => {
  // Admin can perform all actions
  if (userRole === 'admin') {
    return true;
  }

  // Define action-based permissions for other roles
  const permissions = {
    faculty: {
      view: true,
      create: false,
      update: false,
      delete: false,
      usage: true,
    },
    security: {
      view: true,
      create: false,
      update: false,
      delete: false,
      usage: true,
    }
  };

  const userPermissions = permissions[userRole];
  if (!userPermissions) {
    return false;
  }

  return userPermissions[action] || false;
};

/**
 * Predefined API key permission combinations
 */
export const apiKeyPermissions = {
  // Admin only actions
  adminOnly: [checkApiKeyAccess, (req, res, next) => {
    if (req.userRole !== 'admin') {
      return res.status(403).json({
        success: false,
        message: "Access denied - admin access required"
      });
    }
    next();
  }],

  // Admin or key owner
  adminOrOwner: [checkApiKeyAccess, validateApiKeyOwnership],

  // Any authenticated user with API key access
  authenticated: [checkApiKeyAccess],

  // Filter results based on access level
  filtered: [checkApiKeyAccess, filterApiKeysByAccess],
};
