// Environment variables check script using the new configuration system
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

async function checkEnvironment() {
    console.log("=== Environment Variables Check ===");
    console.log("NODE_ENV:", process.env.NODE_ENV || "undefined");
    console.log("PORT:", process.env.PORT || "undefined");
    console.log("ENVIRONMENT:", process.env.ENVIRONMENT || "undefined");
    console.log("");

    console.log("=== Client URLs ===");
    console.log("CLIENT_URL_LOCAL:", process.env.CLIENT_URL_LOCAL || "undefined");
    console.log("CLIENT_URL_DEV:", process.env.CLIENT_URL_DEV || "undefined");
    console.log("CLIENT_URL_PRO:", process.env.CLIENT_URL_PRO || "undefined");
    console.log("");

    console.log("=== Backend URLs ===");
    console.log("BACKEND_URL_LOCAL:", process.env.BACKEND_URL_LOCAL || "undefined");
    console.log("BACKEND_URL_DEV:", process.env.BACKEND_URL_DEV || "undefined");
    console.log("BACKEND_URL_PRO:", process.env.BACKEND_URL_PRO || "undefined");
    console.log("");

    console.log("=== Additional Configuration ===");
    console.log("CORS_ADDITIONAL_ORIGINS:", process.env.CORS_ADDITIONAL_ORIGINS || "undefined");
    console.log("MONGO_URI:", process.env.MONGO_URI ? "Set" : "Not set");
    console.log("JWT_SECRET:", process.env.JWT_SECRET ? "Set" : "Not set");
    console.log("GOOGLE_CLIENT_ID:", process.env.GOOGLE_CLIENT_ID ? "Set" : "Not set");
    console.log("GOOGLE_CLIENT_SECRET:", process.env.GOOGLE_CLIENT_SECRET ? "Set" : "Not set");
    console.log("=====================================");

    console.log("");
    console.log("=== Configuration Test ===");
    try {
        // Dynamically import config after environment variables are loaded
        const { config } = await import("./utils/config.js");
        
        console.log("🔧 Current Environment:", config.environment);
        console.log("🔧 Client URL:", config.urls.client);
        console.log("🔧 Backend URL:", config.urls.backend);
        console.log("🔧 OAuth Callback:", config.urls.oauthCallback);
        console.log("🔧 CORS Origins:", config.cors.origins);
        console.log("✅ Configuration loaded successfully");

        console.log("");
        console.log("=== CORS Test ===");
        // Test CORS with current configuration
        const testOrigins = [
            config.urls.client,
            'http://localhost:3203',
            'http://localhost:5173',
        ];

        testOrigins.forEach(origin => {
            const isAllowed = config.cors.origins.includes(origin);
            console.log(`${origin}: ${isAllowed ? '✅ ALLOWED' : '❌ BLOCKED'}`);
        });

    } catch (error) {
        console.error("❌ Configuration error:", error.message);
    }

    console.log("=====================================");
}

// Run the check
checkEnvironment().catch(console.error);
