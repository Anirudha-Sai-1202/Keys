/**
 * Environment-based configuration utility for backend
 * Supports: local, dev, pro environments
 */

/**
 * Get the current environment
 * @returns {string} 'local' | 'dev' | 'pro'
 */
export const getEnvironment = () => {
  const env = process.env.ENVIRONMENT?.toLowerCase();
  if (!['local', 'dev', 'pro'].includes(env)) {
    console.warn(`Invalid ENVIRONMENT: ${env}. Defaulting to 'local'`);
    return 'local';
  }
  
  return env;
};

/**
 * Get client URL based on current environment
 * @returns {string} The client/frontend URL
 */
export const getClientUrl = () => {
  const env = getEnvironment();

  const urls = {
    local: process.env.CLIENT_URL_LOCAL,
    dev: process.env.CLIENT_URL_DEV,
    pro: process.env.CLIENT_URL_PRO
  };

  const clientUrl = urls[env];

  // Validate that the URL is set
  if (!clientUrl) {
    throw new Error(`Missing Client URL for environment: ${env}. Please set CLIENT_URL_${env.toUpperCase()} in .env file.`);
  }

  return clientUrl;
};

/**
 * Get backend URL based on current environment (for OAuth callbacks)
 * @returns {string} The backend URL
 */
export const getBackendUrl = () => {
  const env = getEnvironment();

  const urls = {
    local: process.env.BACKEND_URL_LOCAL,
    dev: process.env.BACKEND_URL_DEV,
    pro: process.env.BACKEND_URL_PRO
  };

  const backendUrl = urls[env];

  // Validate that the URL is set
  if (!backendUrl) {
    throw new Error(`Missing Backend URL for environment: ${env}. Please set BACKEND_URL_${env.toUpperCase()} in .env file.`);
  }

  return backendUrl;
};

/**
 * Get OAuth callback URL
 * @returns {string} The OAuth callback URL
 */
export const getOAuthCallbackUrl = () => {
  const backendUrl = getBackendUrl();
  const env = getEnvironment();

  // For local environment, use direct /api path (no /be prefix)
  if (env === 'local') {
    return `${backendUrl}/api/auth/google/callback`;
  }

  // For dev/pro environments, check if /be is already in the URL
  return backendUrl.includes('/be')
    ? `${backendUrl}/api/auth/google/callback`
    : `${backendUrl}/be/api/auth/google/callback`;
};

/**
 * Get CORS allowed origins based on environment
 * @returns {string[]} Array of allowed origins
 */
export const getCorsOrigins = () => {
  const env = getEnvironment();

  // Get base origins from environment variables
  const baseOrigins = [];

  // Add environment-specific client URLs
  if (process.env.CLIENT_URL_LOCAL) baseOrigins.push(process.env.CLIENT_URL_LOCAL);
  if (process.env.CLIENT_URL_DEV) {
    baseOrigins.push(process.env.CLIENT_URL_DEV);
    baseOrigins.push(process.env.CLIENT_URL_DEV + '/be');
  }
  if (process.env.CLIENT_URL_PRO) {
    baseOrigins.push(process.env.CLIENT_URL_PRO);
    baseOrigins.push(process.env.CLIENT_URL_PRO + '/be');
  }

  // Add additional CORS origins from environment variables if they exist
  if (process.env.CORS_ADDITIONAL_ORIGINS) {
    const additionalOrigins = process.env.CORS_ADDITIONAL_ORIGINS.split(',').map(origin => origin.trim());
    baseOrigins.push(...additionalOrigins);
  }

  // For local environment, add common development ports
  const envOrigins = {
    local: [
      'http://localhost:3203',
      'http://localhost:3204',
      'http://localhost:3205',
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:3203',
      'http://127.0.0.1:3204',
      'http://127.0.0.1:3205',
      'http://127.0.0.1:5173',
      'https://vnr-keys.vercel.app',
      'https://vnr-keys-1.onrender.com'
    ],
    dev: [
      'http://localhost:3203', // For local development against dev backend
      'http://localhost:3204',
      'http://localhost:5173',
      'https://vnr-keys.vercel.app',
      'https://vnr-keys-1.onrender.com'
    ],
    pro: []
  };

  const allOrigins = [...baseOrigins, ...envOrigins[env]];

  // Remove duplicates
  return [...new Set(allOrigins)];
};

/**
 * Configuration object with all settings
 */
export const config = {
  environment: getEnvironment(),
  server: {
    port: process.env.PORT,
    nodeEnv: process.env.NODE_ENV
  },
  urls: {
    client: getClientUrl(),
    backend: getBackendUrl(),
    oauthCallback: getOAuthCallbackUrl()
  },
  cors: {
    origins: getCorsOrigins()
  },
  database: {
    mongoUri: process.env.MONGO_URI
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET,
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET
    }
  },
  email: {
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true',
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
    from: process.env.EMAIL_FROM,
    fromName: process.env.EMAIL_FROM_NAME
  }
};

// Log configuration in development
if (config.environment === 'local' || config.server.nodeEnv === 'development') {
  console.log('🔧 BACKEND CONFIG:', {
    environment: config.environment,
    clientUrl: config.urls.client,
    backendUrl: config.urls.backend,
    oauthCallback: config.urls.oauthCallback,
    corsOrigins: config.cors.origins
  });
}

export default config;
