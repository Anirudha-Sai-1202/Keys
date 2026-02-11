// Environment configuration - must be imported first
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Export environment variables for easy access
export const {
  NODE_ENV,
  PORT,
  MONGO_URI,
  JWT_SECRET,
  ENVIRONMENT,
  CLIENT_URL_LOCAL,
  CLIENT_URL_DEV,
  CLIENT_URL_PRO,
  BACKEND_URL_LOCAL,
  BACKEND_URL_DEV,
  BACKEND_URL_PRO,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  AUTH_SERVER_URL_LOCAL,
  AUTH_SERVER_URL_DEV,
  AUTH_SERVER_URL_PRO,
  APP_NAME,
  EMAIL_HOST,
  EMAIL_PORT,
  EMAIL_USER,
  EMAIL_PASS,
  EMAIL_FROM,
  EMAIL_FROM_NAME
} = process.env;


// Validate required environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  process.exit(1);
}

console.log('✅ Environment variables loaded successfully');
console.log('🔍 OAuth credentials:', {
  GOOGLE_CLIENT_ID: GOOGLE_CLIENT_ID ? '✅ Set' : '❌ Missing',
  GOOGLE_CLIENT_SECRET: GOOGLE_CLIENT_SECRET ? '✅ Set' : '❌ Missing'
});
