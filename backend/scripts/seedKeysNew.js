import mongoose from "mongoose";
import dotenv from "dotenv";
import Key from "../models/key.model.js";

dotenv.config();

const sampleKeys = [
  {
    "keyNumber": "1",
    "keyName": ["A001"],
    "location": "Ground Floor - Block A",
    "description": "class Room",
    "category": "classroom",
    "department": "class",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "1",
    "keyName": ["A002"],
    "location": "Ground Floor - Block A",
    "description": "Staff Room",
    "category": "classroom",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "1",
    "keyName": ["A003"],
    "location": "Ground Floor - Block A",
    "description": "SSC",
    "category": "facility",
    "department": "SSC",
    "frequentlyUsed": false
  }
];

// Transform the data with unique keyNumbers
const transformedKeys = sampleKeys.map((key, index) => {
  const keyName = Array.isArray(key.keyName) ? key.keyName.join('/') : key.keyName;
  const location = key.location.replace(/\s+/g, '_').replace(/-/g, '_');
  
  return {
    ...key,
    keyNumber: `${keyName}_${location}_${index}`, // Guaranteed unique
    keyName: keyName,
    department: key.department === 'class' ? 'COMMON' : 
                key.department === 'SSC' ? 'ADMIN' : 
                key.department || 'COMMON',
    category: key.category === 'facility' ? 'other' : key.category
  };
});

const seedKeys = async () => {
  try {
    console.log("Connecting to MongoDB...");
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB successfully");

    // Clear existing keys
    console.log("Clearing existing keys...");
    await Key.deleteMany({});
    console.log("Existing keys cleared");

    // Insert sample keys
    console.log("Inserting transformed keys...");
    console.log("Sample transformed key:", transformedKeys[0]);
    
    const insertedKeys = await Key.insertMany(transformedKeys);
    console.log(`${insertedKeys.length} keys inserted successfully`);

    console.log("\n✅ Key seeding completed successfully!");
    
  } catch (error) {
    console.error("❌ Error seeding keys:", error.message);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log("Database connection closed");
    process.exit(0);
  }
};

// Run the seed function
seedKeys();
