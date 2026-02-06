#!/usr/bin/env node

// Startup script with environment debugging
import dotenv from "dotenv";
import path from "path";

// Load environment variables
dotenv.config();

console.log("=== STARTUP ENVIRONMENT CHECK ===");
console.log("NODE_ENV:", process.env.NODE_ENV || "undefined");
console.log("PORT:", process.env.PORT || "undefined");
console.log("ENVIRONMENT:", process.env.ENVIRONMENT || "undefined");
console.log("CLIENT_URL_DEV:", process.env.CLIENT_URL_DEV || "undefined");
console.log("CLIENT_URL_PRO:", process.env.CLIENT_URL_PRO || "undefined");
console.log("CLIENT_URL_LOCAL:", process.env.CLIENT_URL_LOCAL || "undefined");
console.log("MONGO_URI:", process.env.MONGO_URI ? "SET" : "undefined");
console.log("JWT_SECRET:", process.env.JWT_SECRET ? "SET" : "undefined");
console.log("Current working directory:", process.cwd());
console.log("__dirname equivalent:", path.resolve());
console.log("=====================================");

// Import and start the main application
import("./index.js").catch(error => {
    console.error("Failed to start application:", error);
    process.exit(1);
});
