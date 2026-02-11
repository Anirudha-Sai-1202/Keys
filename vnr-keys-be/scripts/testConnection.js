import mongoose from "mongoose";
import dotenv from "dotenv";
import Key from "../models/key.model.js";
import User from "../models/user.model.js";

dotenv.config();

const testConnection = async () => {
  try {
    console.log("🔄 Testing MongoDB connection...");
    console.log("MongoDB URI:", process.env.MONGO_URI.replace(/\/\/([^:]+):([^@]+)@/, "//***:***@"));
    
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB successfully");
    
    // Get database name
    const dbName = mongoose.connection.db.databaseName;
    console.log("📊 Database name:", dbName);
    
    // List all collections
    const collections = await mongoose.connection.db.listCollections().toArray();
    console.log("📁 Collections in database:");
    collections.forEach(collection => {
      console.log(`  - ${collection.name}`);
    });
    
    // Test Key model
    console.log("\n🔑 Testing Key model...");
    const keyCount = await Key.countDocuments();
    console.log(`Keys in vnrkeys collection: ${keyCount}`);
    
    if (keyCount > 0) {
      const sampleKey = await Key.findOne();
      console.log("Sample key:", {
        keyNumber: sampleKey.keyNumber,
        keyName: sampleKey.keyName,
        location: sampleKey.location,
        status: sampleKey.status,
      });
    }
    
    // Test User model
    console.log("\n👤 Testing User model...");
    const userCount = await User.countDocuments();
    console.log(`Users in users collection: ${userCount}`);
    
    if (userCount > 0) {
      const sampleUser = await User.findOne().select('name email role');
      console.log("Sample user:", {
        name: sampleUser.name,
        email: sampleUser.email,
        role: sampleUser.role,
      });
    }
    
    console.log("\n✅ Database connection test completed successfully!");
    
  } catch (error) {
    console.error("❌ Database connection test failed:", error.message);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log("🔌 Database connection closed");
    process.exit(0);
  }
};

// Run the test
testConnection();
