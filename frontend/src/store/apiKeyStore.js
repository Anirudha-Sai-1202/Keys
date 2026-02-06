import { create } from "zustand";
import axios from "axios";
import { handleError, handleSuccess } from "../utils/errorHandler.js";
import { config } from "../utils/config.js";

const API_URL = `${config.api.baseUrl}/api-keys`;

// Helper function to transform backend API key data to frontend format
const transformApiKeyData = (backendKey) => {
  return {
    id: backendKey._id,
    keyId: backendKey.keyId,
    keyName: backendKey.keyName,
    apiKey: backendKey.apiKey,
    department: backendKey.department,
    description: backendKey.description || "",
    permissions: backendKey.permissions,
    rateLimit: backendKey.rateLimit,
    isActive: backendKey.isActive,
    isStatic: backendKey.isStatic,
    createdBy: backendKey.createdBy,
    lastUsed: backendKey.lastUsed,
    usageCount: backendKey.usageCount,
    createdAt: backendKey.createdAt,
    updatedAt: backendKey.updatedAt
  };
};

export const useApiKeyStore = create((set, get) => ({
  apiKeys: [],
  isLoading: false,
  error: null,
  stats: null,

  // Get API keys by status
  getActiveApiKeys: () => {
    const { apiKeys } = get();
    return apiKeys.filter(key => key.isActive);
  },

  getStaticApiKeys: () => {
    const { apiKeys } = get();
    return apiKeys.filter(key => key.isStatic && key.isActive);
  },

  getDynamicApiKeys: () => {
    const { apiKeys } = get();
    return apiKeys.filter(key => !key.isStatic && key.isActive);
  },

  // Get API keys by department
  getApiKeysByDepartment: (department) => {
    const { apiKeys } = get();
    return apiKeys.filter(key => key.department === department && key.isActive);
  },

  // Search API keys
  searchApiKeys: (query) => {
    const { apiKeys } = get();
    if (!query.trim()) return apiKeys;

    const searchTerm = query.toLowerCase();
    return apiKeys.filter(key =>
      key.keyId?.toLowerCase().includes(searchTerm) ||
      key.keyName?.toLowerCase().includes(searchTerm) ||
      key.department?.toLowerCase().includes(searchTerm) ||
      key.description?.toLowerCase().includes(searchTerm)
    );
  },

  // Fetch all API keys from API (admin only)
  fetchApiKeys: async () => {
    set({ isLoading: true, error: null });

    try {
      const response = await axios.get(API_URL, {
        withCredentials: true,
      });

      const backendKeys = response.data.data.keys || [];
      const apiKeys = backendKeys.map(transformApiKeyData);

      set({ apiKeys, isLoading: false });
      return apiKeys;
    } catch (error) {
      console.error("Error fetching API keys:", error);
      const errorMessage = handleError(error);
      set({ apiKeys: [], error: errorMessage, isLoading: false });
      throw error;
    }
  },

  // Fetch API key statistics
  fetchApiKeyStats: async () => {
    try {
      const response = await axios.get(`${API_URL}/stats`, {
        withCredentials: true,
      });

      const stats = response.data.data;
      set({ stats });
      return stats;
    } catch (error) {
      console.error("Error fetching API key statistics:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage });
      throw error;
    }
  },

  // Fetch API keys by department
  fetchApiKeysByDepartment: async (department) => {
    set({ isLoading: true, error: null });

    try {
      const response = await axios.get(`${API_URL}/department/${department}`, {
        withCredentials: true,
      });

      const backendKeys = response.data.data.keys || [];
      const apiKeys = backendKeys.map(transformApiKeyData);

      return apiKeys;
    } catch (error) {
      console.error("Error fetching API keys by department:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage, isLoading: false });
      throw error;
    }
  },

  // Create a new API key (admin only)
  createApiKey: async (keyData) => {
    set({ isLoading: true, error: null });

    try {
      const response = await axios.post(API_URL, keyData, {
        withCredentials: true,
      });

      const newKey = transformApiKeyData(response.data.data.key);
      const { apiKeys } = get();
      const updatedKeys = [...apiKeys, newKey];

      set({ apiKeys: updatedKeys, isLoading: false });
      handleSuccess(response.data.message);
      return newKey;
    } catch (error) {
      console.error("Error creating API key:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage, isLoading: false });
      throw error;
    }
  },

  // Update an existing API key (admin only)
  updateApiKey: async (keyId, keyData) => {
    set({ isLoading: true, error: null });

    try {
      const response = await axios.put(`${API_URL}/${keyId}`, keyData, {
        withCredentials: true,
      });

      const updatedKey = transformApiKeyData(response.data.data.key);
      const { apiKeys } = get();
      const updatedKeys = apiKeys.map(key =>
        key.keyId === keyId ? updatedKey : key
      );

      set({ apiKeys: updatedKeys, isLoading: false });
      handleSuccess(response.data.message);
      return updatedKey;
    } catch (error) {
      console.error("Error updating API key:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage, isLoading: false });
      throw error;
    }
  },

  // Delete an API key (admin only)
  deleteApiKey: async (keyId) => {
    set({ isLoading: true, error: null });

    try {
      const response = await axios.delete(`${API_URL}/${keyId}`, {
        withCredentials: true,
      });

      const { apiKeys } = get();
      const updatedKeys = apiKeys.filter(key => key.keyId !== keyId);

      set({ apiKeys: updatedKeys, isLoading: false });
      handleSuccess(response.data.message);
      return true;
    } catch (error) {
      console.error("Error deleting API key:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage, isLoading: false });
      throw error;
    }
  },

  // Record API key usage
  recordApiKeyUsage: async (keyId) => {
    try {
      const response = await axios.post(`${API_URL}/${keyId}/usage`, {}, {
        withCredentials: true,
      });

      // Update the usage count in the store
      const { apiKeys } = get();
      const updatedKeys = apiKeys.map(key =>
        key.keyId === keyId 
          ? { ...key, usageCount: response.data.data.usageCount, lastUsed: response.data.data.lastUsed }
          : key
      );

      set({ apiKeys: updatedKeys });
      return response.data.data;
    } catch (error) {
      console.error("Error recording API key usage:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage });
      throw error;
    }
  },

  // Get a single API key by keyId
  getApiKeyById: async (keyId) => {
    try {
      const response = await axios.get(`${API_URL}/${keyId}`, {
        withCredentials: true,
      });

      return transformApiKeyData(response.data.data.key);
    } catch (error) {
      console.error("Error fetching API key:", error);
      const errorMessage = handleError(error);
      set({ error: errorMessage });
      throw error;
    }
  },

  // Clear error
  clearError: () => {
    set({ error: null });
  },

  // Reset store
  reset: () => {
    set({
      apiKeys: [],
      isLoading: false,
      error: null,
      stats: null
    });
  }
}));
