import mongoose from "mongoose";
import dotenv from "dotenv";
import Key from "../models/key.model.js";

dotenv.config();

const sampleKeys = [
  {
    "keyNumber": "A001",
    "keyName": "A001",
    "location": "Ground Floor - Block A",
    "description": "Class Room",
    "category": "classroom",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A002",
    "keyName": "A002",
    "location": "Ground Floor - Block A",
    "description": "Staff Room",
    "category": "classroom",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A003",
    "keyName": "A003",
    "location": "Ground Floor - Block A",
    "description": "SSC",
    "category": "office",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A004",
    "keyName": "A004",
    "location": "Ground Floor - Block A",
    "description": "Library",
    "category": "library",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A005",
    "keyName": "A005",
    "location": "Ground Floor - Block A",
    "description": "Students Gores",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A006",
    "keyName": "A006/A009",
    "location": "Ground Floor - Block A",
    "description": "MT Lab Workshop",
    "category": "lab",
    "department": "MECH",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A007",
    "keyName": "A007/A008",
    "location": "Ground Floor - Block A",
    "description": "Workshop-1",
    "category": "lab",
    "department": "MECH",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A010",
    "keyName": "A010",
    "location": "Ground Floor - Block A",
    "description": "Staff Room",
    "category": "classroom",
    "department": "MECH",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A011",
    "keyName": "A011",
    "location": "Ground Floor - Block A",
    "description": "Washroom",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A012",
    "keyName": "A012",
    "location": "Ground Floor - Block A",
    "description": "FM Lab Workshop-2",
    "category": "lab",
    "department": "MECH",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A013",
    "keyName": "A013",
    "location": "Ground Floor - Block A",
    "description": "Class Room",
    "category": "classroom",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B001",
    "keyName": "B001",
    "location": "Ground Floor - Block B",
    "description": "General Room",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B002",
    "keyName": "B002",
    "location": "Ground Floor - Block B",
    "description": "Staff Room",
    "category": "classroom",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B003",
    "keyName": "B003",
    "location": "Ground Floor - Block B",
    "description": "HOD Room",
    "category": "office",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B004",
    "keyName": "B004",
    "location": "Ground Floor - Block B",
    "description": "BEE Lab",
    "category": "lab",
    "department": "EEE",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B005",
    "keyName": "B005/B006",
    "location": "Ground Floor - Block B",
    "description": "EM Lab",
    "category": "lab",
    "department": "EEE",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B007",
    "keyName": "B007/B008",
    "location": "Ground Floor - Block B",
    "description": "TE Lab",
    "category": "lab",
    "department": "MECH",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B009",
    "keyName": "B009/B010",
    "location": "Ground Floor - Block B",
    "description": "Washroom",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "B011",
    "keyName": "B011",
    "location": "Ground Floor - Block B",
    "description": "Seminar Hall",
    "category": "auditorium",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "C001",
    "keyName": "C001",
    "location": "Ground Floor - Block C",
    "description": "KS Auditorium",
    "category": "auditorium",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "C002",
    "keyName": "C002",
    "location": "Ground Floor - Block C",
    "description": "Panel Room",
    "category": "office",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "C003",
    "keyName": "C003",
    "location": "Ground Floor - Block C",
    "description": "Transport Office",
    "category": "office",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "C004",
    "keyName": "C004",
    "location": "Ground Floor - Block C",
    "description": "Lunch Room",
    "category": "cafeteria",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "C005",
    "keyName": "C005/C006",
    "location": "Ground Floor - Block C",
    "description": "Washroom",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "C007",
    "keyName": "C007/C008",
    "location": "Ground Floor - Block C",
    "description": "Engineering Lab Workshop-II",
    "category": "lab",
    "department": "MECH",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A101",
    "keyName": "A101",
    "location": "First Floor - Block A",
    "description": "Staff Room",
    "category": "classroom",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A102",
    "keyName": "A102",
    "location": "First Floor - Block A",
    "description": "COE Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A103",
    "keyName": "A103",
    "location": "First Floor - Block A",
    "description": "Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A104",
    "keyName": "A104/A105",
    "location": "First Floor - Block A",
    "description": "Washroom",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A106",
    "keyName": "A106",
    "location": "First Floor - Block A",
    "description": "Control Room",
    "category": "office",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A107",
    "keyName": "A107",
    "location": "First Floor - Block A",
    "description": "Panel Room",
    "category": "office",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A108",
    "keyName": "A108",
    "location": "First Floor - Block A",
    "description": "OOP Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A109",
    "keyName": "A109/A110",
    "location": "First Floor - Block A",
    "description": "Computer Graphics Lab",
    "category": "lab",
    "department": "CSE",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A111",
    "keyName": "A111",
    "location": "First Floor - Block A",
    "description": "ITWS Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A112",
    "keyName": "A112",
    "location": "First Floor - Block A",
    "description": "SE Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A113",
    "keyName": "A113",
    "location": "First Floor - Block A",
    "description": "TP Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A114",
    "keyName": "A114",
    "location": "First Floor - Block A",
    "description": "ML Lab",
    "category": "lab",
    "department": "IT",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A115",
    "keyName": "A115/A116",
    "location": "First Floor - Block A",
    "description": "Washroom",
    "category": "other",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A117",
    "keyName": "A117",
    "location": "First Floor - Block A",
    "description": "ECS Lab",
    "category": "lab",
    "department": "Other",
    "frequentlyUsed": false
  },
  {
    "keyNumber": "A118",
    "keyName": "A118",
    "location": "First Floor - Block A",
    "description": "ECS Lab",
    "category": "lab",
    "department": "Other",
    "frequentlyUsed": false
  }
];

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
    console.log("Inserting sample keys...");
    const insertedKeys = await Key.insertMany(sampleKeys);
    console.log(`${insertedKeys.length} keys inserted successfully`);

    // Display inserted keys
    console.log("\nInserted Keys:");
    insertedKeys.forEach((key, index) => {
      console.log(`${index + 1}. ${key.keyNumber} - ${key.keyName} (${key.location})`);
    });

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
