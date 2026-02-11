/**
 * Environment-based configuration utility
 * Supports: local, dev, pro environments
 */

/**
 * Get the current environment
 * @returns {string} 'local' | 'dev' | 'pro'
 */
export const getEnvironment = () => {
  const env = import.meta.env.VITE_ENVIRONMENT?.toLowerCase();

  // Validate environment
  if (!['local', 'dev', 'pro'].includes(env)) {
    console.warn(`Invalid VITE_ENVIRONMENT: ${env}. Defaulting to 'local'`);
    return 'local';
  }

  return env;
};

/**
 * Get API URL based on current environment
 * @returns {string} The API base URL
 */
export const getApiUrl = () => {
  const env = getEnvironment();

  const urls = {
    local: import.meta.env.VITE_API_URL_LOCAL,
    dev: import.meta.env.VITE_API_URL_DEV,
    pro: import.meta.env.VITE_API_URL_PRO
  };

  const apiUrl = urls[env];

  // Validate that the URL is set
  if (!apiUrl) {
    throw new Error(`Missing API URL for environment: ${env}. Please set VITE_API_URL_${env.toUpperCase()} in .env file.`);
  }

  // Debug logging in development
  // if (env === 'local' || import.meta.env.DEV) {
  //   console.log(`🔧 CONFIG: Environment = ${env}`);
  //   console.log(`🔧 CONFIG: API URL = ${apiUrl}`);
  // }

  return apiUrl;
};

/**
 * Get frontend URL based on current environment
 * @returns {string} The frontend base URL
 */
export const getFrontendUrl = () => {
  const env = getEnvironment();

  const urls = {
    local: import.meta.env.VITE_FRONTEND_URL_LOCAL,
    dev: import.meta.env.VITE_FRONTEND_URL_DEV,
    pro: import.meta.env.VITE_FRONTEND_URL_PRO
  };

  const frontendUrl = urls[env];

  // Validate that the URL is set
  if (!frontendUrl) {
    throw new Error(`Missing Frontend URL for environment: ${env}. Please set VITE_FRONTEND_URL_${env.toUpperCase()} in .env file.`);
  }

  return frontendUrl;
};

/**
 * Get Socket.IO server URL (API URL without /api suffix)
 * @returns {string} The Socket.IO server URL
 */
export const getSocketUrl = () => {
  const apiUrl = getApiUrl();
  return apiUrl.replace('/api', '');
};

/**
 * Get auth server URL based on current environment
 * @returns {string} The auth server URL
 */
export const getAuthServerUrl = () => {
  const env = getEnvironment();

  const urls = {
    local: "http://localhost:2999",
    dev: import.meta.env.VITE_AUTH_SERVER_URL_DEV,
    pro: import.meta.env.VITE_AUTH_SERVER_URL_PRO
  };

  const authServerUrl = urls[env];

  // Validate that the URL is set
  if (!authServerUrl) {
    console.warn(`Missing Auth Server URL for environment: ${env}. SSO features will be disabled.`);
    return null;
  }

  return authServerUrl;
};

/**
 * Configuration object with all URLs
 */
export const config = {
  environment: getEnvironment(),
  api: {
    baseUrl: getApiUrl(),
    authUrl: `${getApiUrl()}/auth`,
    keysUrl: `${getApiUrl()}/keys`,
    dashboardUrl: `${getApiUrl()}/dashboard`
  },
  frontend: {
    baseUrl: getFrontendUrl()
  },
  socket: {
    url: getSocketUrl()
  },
  sso: {
    serverUrl: getAuthServerUrl(),
    appName: import.meta.env.VITE_APP_NAME || 'keys'
  },
  app: {
    name: import.meta.env.VITE_APP_NAME,
    version: import.meta.env.VITE_APP_VERSION
  },
  // QR-related configuration
  qr: {
    // Use env override if provided, default to 60 seconds
    validitySeconds: (() => {
      const v = Number(import.meta.env.VITE_QR_VALIDITY_SECONDS);
      return Number.isFinite(v) && v > 0 ? v : 60;
    })()
  }
};

// Log configuration in development
if (config.environment === 'local' || import.meta.env.DEV) {
  console.log('🔧 APP CONFIG:', config);
}

export default config;
