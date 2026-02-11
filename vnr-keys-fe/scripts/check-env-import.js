#!/usr/bin/env node
/* eslint-env node */
/**
 * Frontend Environment Import Check Script
 * Tests if .env file is being imported correctly by Vite
 */

import fs from "fs";
import path from "path";

console.log("🔍 Frontend Environment Import Check");
console.log("====================================");

// Check if .env file exists
const envPath = path.resolve(process.cwd(), '.env');
console.log("📁 Checking .env file location:", envPath);

if (fs.existsSync(envPath)) {
    console.log("✅ .env file found");
    
    // Read .env file content
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envLines = envContent.split('\n').filter(line => line.trim() && !line.startsWith('#'));
    console.log(`📄 .env file contains ${envLines.length} environment variables`);
    
    // Show VITE_ prefixed variables
    const viteVars = envLines.filter(line => line.startsWith('VITE_'));
    console.log(`🔧 VITE_ prefixed variables: ${viteVars.length}`);
    
    console.log("\n📋 VITE Environment Variables in .env:");
    viteVars.forEach(line => {
        const [key, ...valueParts] = line.split('=');
        const value = valueParts.join('=').trim();
        console.log(`   ${key} = ${value}`);
    });
    
} else {
    console.log("❌ .env file not found");
    process.exit(1);
}

console.log("\n🧪 Testing Vite Environment Import:");
console.log("===================================");

// Define expected Vite environment variables
const expectedViteVars = [
    'VITE_ENVIRONMENT',
    'VITE_APP_NAME',
    'VITE_APP_VERSION',
    'VITE_API_URL_LOCAL',
    'VITE_API_URL_DEV',
    'VITE_API_URL_PRO',
    'VITE_FRONTEND_URL_LOCAL',
    'VITE_FRONTEND_URL_DEV',
    'VITE_FRONTEND_URL_PRO'
];

// Since this is a Node.js script, we can't access import.meta.env
// We'll simulate what Vite would do by reading the .env file
const envContent = fs.readFileSync(envPath, 'utf8');
const envVars = {};

envContent.split('\n').forEach(line => {
    if (line.trim() && !line.startsWith('#') && line.includes('=')) {
        const [key, ...valueParts] = line.split('=');
        const value = valueParts.join('=').trim();
        envVars[key.trim()] = value;
    }
});

console.log("📊 Environment Variables Status:");
console.log("================================");

let missingRequired = [];
let foundRequired = [];

expectedViteVars.forEach(varName => {
    if (envVars[varName]) {
        foundRequired.push(varName);
        console.log(`✅ ${varName}: ${envVars[varName]}`);
    } else {
        missingRequired.push(varName);
        console.log(`❌ ${varName}: Missing`);
    }
});

console.log("\n🔧 Testing Configuration Logic:");
console.log("===============================");

// Simulate the frontend config logic
const environment = envVars['VITE_ENVIRONMENT'] || 'local';
console.log(`🌍 Environment: ${environment}`);

const apiUrls = {
    local: envVars['VITE_API_URL_LOCAL'],
    dev: envVars['VITE_API_URL_DEV'],
    pro: envVars['VITE_API_URL_PRO']
};

const frontendUrls = {
    local: envVars['VITE_FRONTEND_URL_LOCAL'],
    dev: envVars['VITE_FRONTEND_URL_DEV'],
    pro: envVars['VITE_FRONTEND_URL_PRO']
};

const selectedApiUrl = apiUrls[environment];
const selectedFrontendUrl = frontendUrls[environment];

if (selectedApiUrl) {
    console.log(`✅ API URL for ${environment}: ${selectedApiUrl}`);
} else {
    console.log(`❌ API URL for ${environment}: Missing`);
}

if (selectedFrontendUrl) {
    console.log(`✅ Frontend URL for ${environment}: ${selectedFrontendUrl}`);
} else {
    console.log(`❌ Frontend URL for ${environment}: Missing`);
}

console.log("\n📊 Summary:");
console.log("===========");
console.log(`✅ Required VITE variables found: ${foundRequired.length}/${expectedViteVars.length}`);

if (missingRequired.length > 0) {
    console.log(`❌ Missing required variables: ${missingRequired.join(', ')}`);
}

console.log("\n💡 Vite Environment Import Notes:");
console.log("=================================");
console.log("• Vite only exposes variables prefixed with VITE_");
console.log("• Variables are available at import.meta.env.VARIABLE_NAME");
console.log("• .env files are loaded automatically by Vite");
console.log("• This script simulates Vite's behavior for testing");

console.log("\n🎯 Frontend Environment Import Test Result:");
console.log("===========================================");

if (missingRequired.length === 0 && selectedApiUrl && selectedFrontendUrl) {
    console.log("🎉 SUCCESS: All required VITE environment variables are configured correctly!");
    console.log("✅ Frontend .env import should work properly with Vite");
    process.exit(0);
} else {
    console.log("💥 FAILURE: Some required VITE environment variables are missing!");
    console.log("Please check your .env file and ensure all VITE_ prefixed variables are set.");
    process.exit(1);
}
