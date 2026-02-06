#!/usr/bin/env node
/**
 * Backend Environment Import Check Script
 * Tests if .env file is being imported correctly
 */

import dotenv from "dotenv";
import path from "path";
import fs from "fs";

console.log("🔍 Backend Environment Import Check");
console.log("=====================================");

// Check if .env file exists
const envPath = path.resolve(process.cwd(), '.env');
console.log("📁 Checking .env file location:", envPath);

if (fs.existsSync(envPath)) {
    console.log("✅ .env file found");
    
    // Read .env file content
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envLines = envContent.split('\n').filter(line => line.trim() && !line.startsWith('#'));
    console.log(`📄 .env file contains ${envLines.length} environment variables`);
} else {
    console.log("❌ .env file not found");
    process.exit(1);
}

console.log("\n🔧 Loading environment variables...");

// Load environment variables
const result = dotenv.config();

if (result.error) {
    console.log("❌ Error loading .env file:", result.error.message);
    process.exit(1);
} else {
    console.log("✅ .env file loaded successfully");
}

console.log("\n📋 Environment Variables Status:");
console.log("================================");

// Define expected environment variables
const expectedVars = [
    'ENVIRONMENT',
    'PORT',
    'MONGO_URI',
    'JWT_SECRET',
    'CLIENT_URL_LOCAL',
    'CLIENT_URL_DEV', 
    'CLIENT_URL_PRO',
    'BACKEND_URL_LOCAL',
    'BACKEND_URL_DEV',
    'BACKEND_URL_PRO',
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'EMAIL_HOST',
    'EMAIL_PORT',
    'EMAIL_USER',
    'EMAIL_PASS',
    'EMAIL_FROM',
    'EMAIL_FROM_NAME'
];

const optionalVars = [
    'NODE_ENV',
    'CORS_ADDITIONAL_ORIGINS',
    'EMAIL_SECURE'
];

let missingRequired = [];
let foundRequired = [];
let foundOptional = [];

// Check required variables
expectedVars.forEach(varName => {
    if (process.env[varName]) {
        foundRequired.push(varName);
        // Mask sensitive values
        const value = ['JWT_SECRET', 'GOOGLE_CLIENT_SECRET', 'EMAIL_PASS'].includes(varName)
            ? '***HIDDEN***'
            : process.env[varName];
        console.log(`✅ ${varName}: ${value}`);
    } else {
        missingRequired.push(varName);
        console.log(`❌ ${varName}: Missing`);
    }
});

// Check optional variables
optionalVars.forEach(varName => {
    if (process.env[varName]) {
        foundOptional.push(varName);
        // Mask sensitive values
        const value = ['JWT_SECRET', 'GOOGLE_CLIENT_SECRET', 'EMAIL_PASS'].includes(varName)
            ? '***HIDDEN***'
            : process.env[varName];
        console.log(`🔵 ${varName}: ${value} (optional)`);
    } else {
        console.log(`⚪ ${varName}: Not set (optional)`);
    }
});

console.log("\n📊 Summary:");
console.log("===========");
console.log(`✅ Required variables found: ${foundRequired.length}/${expectedVars.length}`);
console.log(`🔵 Optional variables found: ${foundOptional.length}/${optionalVars.length}`);

if (missingRequired.length > 0) {
    console.log(`❌ Missing required variables: ${missingRequired.join(', ')}`);
}

console.log("\n🧪 Testing Configuration Import:");
console.log("================================");

try {
    // Test dynamic import of config
    const { config } = await import("../utils/config.js");
    
    console.log("✅ Configuration module imported successfully");
    console.log(`🔧 Current environment: ${config.environment}`);
    console.log(`🌐 Client URL: ${config.urls.client}`);
    console.log(`🔗 Backend URL: ${config.urls.backend}`);
    console.log(`🔒 OAuth Callback: ${config.urls.oauthCallback}`);
    console.log(`🌍 CORS Origins: ${config.cors.origins.length} origins configured`);
    
} catch (error) {
    console.log("❌ Configuration import failed:", error.message);
}

console.log("\n🎯 Environment Import Test Result:");
console.log("==================================");

if (missingRequired.length === 0) {
    console.log("🎉 SUCCESS: All required environment variables are loaded correctly!");
    process.exit(0);
} else {
    console.log("💥 FAILURE: Some required environment variables are missing!");
    console.log("Please check your .env file and ensure all required variables are set.");
    process.exit(1);
}
