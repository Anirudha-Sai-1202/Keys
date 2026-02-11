import mongoose from "mongoose";
import dotenv from "dotenv";
import User from "../models/user.model.js";
import Key from "../models/key.model.js";

dotenv.config();

const testAuth = async () => {
  try {
    console.log("🔄 Testing MongoDB connection and authentication...");
    console.log("MongoDB URI:", process.env.MONGO_URI.replace(/\/\/([^:]+):([^@]+)@/, "//***:***@"));
    
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB successfully");
    
    // Get database name
    const dbName = mongoose.connection.db.databaseName;
    console.log("📊 Database name:", dbName);
    
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
      
      // Find a faculty user
      const facultyUser = await User.findOne({ role: 'faculty' }).select('name email role');
      if (facultyUser) {
        console.log("Faculty user found:", {
          name: facultyUser.name,
          email: facultyUser.email,
          role: facultyUser.role,
        });
      } else {
        console.log("❌ No faculty user found");
      }
    }
    
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
        takenBy: sampleKey.takenBy,
      });
      
      // Find unavailable keys (taken keys)
      const unavailableKeys = await Key.find({ status: 'unavailable' });
      console.log(`Unavailable keys count: ${unavailableKeys.length}`);
      
      if (unavailableKeys.length > 0) {
        console.log("Sample unavailable key:", {
          keyNumber: unavailableKeys[0].keyNumber,
          keyName: unavailableKeys[0].keyName,
          takenBy: unavailableKeys[0].takenBy,
        });
      }
    }
    
    console.log("\n✅ Authentication test completed successfully!");
    
  } catch (error) {
    console.error("❌ Authentication test failed:", error.message);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log("🔌 Database connection closed");
    process.exit(0);
  }
};

// Run the test
testAuth(); 