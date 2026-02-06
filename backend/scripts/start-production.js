#!/usr/bin/env node

/**
 * Start the server in production mode for testing
 * This script sets NODE_ENV to production and starts the server
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Set environment to production
process.env.NODE_ENV = 'production';

console.log('🚀 Starting server in production mode...');
console.log('📝 Logs will be minimal in production mode');
console.log('🔄 Press Ctrl+C to stop the server\n');

// Start the server
const serverProcess = spawn('node', ['index.js'], {
  cwd: path.join(__dirname, '..'),
  stdio: 'inherit',
  env: {
    ...process.env,
    NODE_ENV: 'production'
  }
});

// Handle process termination
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  serverProcess.kill('SIGINT');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down server...');
  serverProcess.kill('SIGTERM');
  process.exit(0);
});

serverProcess.on('close', (code) => {
  console.log(`\n📊 Server process exited with code ${code}`);
  process.exit(code);
});
