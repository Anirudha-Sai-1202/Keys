/**
 * User Import Script for VNR Keys Management System
 *
 * This script imports users with specific roles into the database.
 * It handles both creating new users and updating existing users' roles.
 *
 * Usage:
 *   npm run import:users           - Import users (makes actual changes)
 *   npm run import:users -- --dry-run  - Preview changes without making them
 *   npm run import:users -- -d     - Short form for dry run
 *
 * Features:
 *   - Validates user data before import
 *   - Handles duplicate users gracefully
 *   - Supports dry-run mode for testing
 *   - Provides detailed logging and error handling
 *   - Generates system Google IDs for non-OAuth users
 *
 * @author VNR Keys Management System
 * @version 1.0.0
 */

import mongoose from "mongoose";
import dotenv from "dotenv";
import crypto from "crypto";
import User from "../models/user.model.js";
import { validateEmail, sanitizeEmail } from "../utils/validation.js";

dotenv.config();

// Check for dry-run mode
const isDryRun = process.argv.includes('--dry-run') || process.argv.includes('-d');

/**
 * Generate a unique Google ID for system users
 * This is used for users that need to be created without actual Google OAuth
 */
const generateSystemGoogleId = (email) => {
  // Create a deterministic but unique Google ID based on email
  const hash = crypto.createHash('sha256').update(`system_${email}`).digest('hex');
  return `system_${hash.substring(0, 20)}`;
};

/**
 * Users to be imported with their roles
 */
const usersToImport = [
  {
    email: "23071a7228@vnrvjiet.in",
    name: "Admin User",
    role: "admin",
    description: "Administrative user for system management"
  },
  {
    email: "23071a7251@vnrvjiet.in", 
    name: "Security Officer",
    role: "security",
    description: "Security personnel for access control and monitoring"
  }
];

/**
 * Validate user data before import
 */
const validateUserData = (userData) => {
  const errors = [];

  // Validate email
  const emailValidation = validateEmail(userData.email);
  if (!emailValidation.isValid) {
    errors.push(`Email validation failed: ${emailValidation.message}`);
  }

  // Additional domain validation for vnrvjiet.in
  if (userData.email && !userData.email.toLowerCase().includes('vnrvjiet.in')) {
    console.warn(`⚠️  Warning: Email ${userData.email} is not from vnrvjiet.in domain`);
  }

  // Validate role
  const validRoles = ["faculty", "security", "admin", "pending"];
  if (!validRoles.includes(userData.role)) {
    errors.push(`Invalid role: ${userData.role}. Must be one of: ${validRoles.join(", ")}`);
  }

  // Validate name
  if (!userData.name || userData.name.trim().length < 2) {
    errors.push("Name must be at least 2 characters long");
  }

  if (userData.name && userData.name.trim().length > 50) {
    errors.push("Name must be less than 50 characters long");
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Create or update a user in the database
 */
const createOrUpdateUser = async (userData) => {
  try {
    const sanitizedEmail = sanitizeEmail(userData.email);

    // Check if user already exists
    let existingUser = await User.findOne({ email: sanitizedEmail });

    if (existingUser) {
      console.log(`👤 User ${sanitizedEmail} already exists`);

      // Update role if different
      if (existingUser.role !== userData.role) {
        console.log(`🔄 ${isDryRun ? '[DRY RUN] Would update' : 'Updating'} role from ${existingUser.role} to ${userData.role}`);

        if (!isDryRun) {
          existingUser.role = userData.role;
          existingUser.isVerified = true;
          existingUser.lastLogin = new Date();

          // Clear department and facultyId for non-faculty users
          if (userData.role !== "faculty") {
            existingUser.department = undefined;
            existingUser.facultyId = undefined;
          }

          await existingUser.save({ validateBeforeSave: false });
          console.log(`✅ Updated user ${sanitizedEmail} with role ${userData.role}`);
        }
        return { user: existingUser, action: 'updated' };
      } else {
        console.log(`ℹ️  User ${sanitizedEmail} already has role ${userData.role}`);
        return { user: existingUser, action: 'exists' };
      }
    }
    
    // Create new user
    console.log(`➕ ${isDryRun ? '[DRY RUN] Would create' : 'Creating'} new user: ${sanitizedEmail}`);

    if (isDryRun) {
      // Return mock user for dry run
      const mockUser = {
        email: sanitizedEmail,
        name: userData.name.trim(),
        role: userData.role,
        googleId: generateSystemGoogleId(sanitizedEmail),
        provider: "google",
        isVerified: true,
        lastLogin: new Date(),
        avatar: null,
        bio: userData.description || "",
        keyUsage: new Map()
      };
      console.log(`✅ [DRY RUN] Would create user ${sanitizedEmail} with role ${userData.role}`);
      return { user: mockUser, action: 'created' };
    }

    const userDoc = {
      email: sanitizedEmail,
      name: userData.name.trim(),
      role: userData.role,
      googleId: generateSystemGoogleId(sanitizedEmail),
      provider: "google",
      isVerified: true,
      lastLogin: new Date(),
      avatar: null, // No avatar for system users
      bio: userData.description || "",
      keyUsage: new Map()
    };

    // Only set department and facultyId for faculty users
    if (userData.role === "faculty") {
      userDoc.department = userData.department;
      userDoc.facultyId = userData.facultyId;
    }

    const newUser = new User(userDoc);
    const savedUser = await newUser.save({ validateBeforeSave: false });
    console.log(`✅ Created user ${sanitizedEmail} with role ${userData.role}`);

    return { user: savedUser, action: 'created' };
    
  } catch (error) {
    console.error(`❌ Error creating/updating user ${userData.email}:`, error.message);
    
    if (error.code === 11000) {
      // Handle duplicate key errors
      if (error.keyPattern?.email) {
        throw new Error(`Email ${userData.email} already exists`);
      }
      if (error.keyPattern?.googleId) {
        throw new Error(`Google ID conflict for ${userData.email}`);
      }
    }
    
    throw error;
  }
};

/**
 * Import users into the database
 */
const importUsers = async () => {
  try {
    console.log("🚀 Starting Users Import Process...");
    if (isDryRun) {
      console.log("🔍 DRY RUN MODE - No changes will be made to the database");
    }
    console.log("=" .repeat(50));
    
    // Connect to MongoDB
    console.log("🔌 Connecting to MongoDB...");
    await mongoose.connect("mongodb+srv://hackergkn:karthik@hackathon.xkjyqhh.mongodb.net/?retryWrites=true&w=majority&appName=hackathon");
    console.log("✅ Connected to MongoDB successfully");
    
    // Validate all user data first
    console.log("\n🔍 Validating user data...");
    const validationResults = usersToImport.map((userData, index) => {
      const validation = validateUserData(userData);
      if (!validation.isValid) {
        console.error(`❌ Validation failed for user ${index + 1} (${userData.email}):`);
        validation.errors.forEach(error => console.error(`   - ${error}`));
      }
      return { userData, validation };
    });
    
    // Check if any validation failed
    const failedValidations = validationResults.filter(result => !result.validation.isValid);
    if (failedValidations.length > 0) {
      throw new Error(`Validation failed for ${failedValidations.length} user(s). Please fix the errors above.`);
    }
    
    console.log("✅ All user data validated successfully");
    
    // Import users
    console.log("\n📝 Importing users...");
    const results = [];
    
    for (const userData of usersToImport) {
      try {
        const result = await createOrUpdateUser(userData);
        results.push(result);
      } catch (error) {
        console.error(`❌ Failed to import user ${userData.email}:`, error.message);
        results.push({ userData, error: error.message, action: 'failed' });
      }
    }
    
    // Display results summary
    console.log("\n📋 Import Results Summary:");
    console.log("-" .repeat(80));
    
    const created = results.filter(r => r.action === 'created');
    const updated = results.filter(r => r.action === 'updated');
    const existing = results.filter(r => r.action === 'exists');
    const failed = results.filter(r => r.action === 'failed');
    
    console.log(`✅ Created: ${created.length} users`);
    console.log(`🔄 Updated: ${updated.length} users`);
    console.log(`ℹ️  Already existed: ${existing.length} users`);
    console.log(`❌ Failed: ${failed.length} users`);
    
    // Display detailed results
    if (created.length > 0) {
      console.log("\n🆕 Created Users:");
      created.forEach((result, index) => {
        const user = result.user;
        console.log(`${(index + 1).toString().padStart(2, '0')}. ${user.email.padEnd(30)} | ${user.role.padEnd(10)} | ${user.name}`);
      });
    }
    
    if (updated.length > 0) {
      console.log("\n🔄 Updated Users:");
      updated.forEach((result, index) => {
        const user = result.user;
        console.log(`${(index + 1).toString().padStart(2, '0')}. ${user.email.padEnd(30)} | ${user.role.padEnd(10)} | ${user.name}`);
      });
    }
    
    if (failed.length > 0) {
      console.log("\n❌ Failed Users:");
      failed.forEach((result, index) => {
        console.log(`${(index + 1).toString().padStart(2, '0')}. ${result.userData.email.padEnd(30)} | Error: ${result.error}`);
      });
    }
    
    // Verify imported users
    console.log("\n🔍 Verifying imported users...");
    for (const userData of usersToImport) {
      const user = await User.findOne({ email: sanitizeEmail(userData.email) });
      if (user && user.role === userData.role) {
        console.log(`✅ Verified: ${user.email} has role ${user.role}`);
      } else {
        console.log(`❌ Verification failed: ${userData.email}`);
      }
    }
    
    console.log("\n" + "=" .repeat(50));
    console.log("✅ Users import completed successfully!");
    console.log("\n📊 Final Statistics:");
    console.log(`   👥 Total users processed: ${usersToImport.length}`);
    console.log(`   ✅ Successful operations: ${created.length + updated.length + existing.length}`);
    console.log(`   ❌ Failed operations: ${failed.length}`);
    
    if (failed.length === 0) {
      console.log("\n🎉 All users imported successfully!");
      if (isDryRun) {
        console.log("\n💡 This was a dry run. To apply changes, run without --dry-run flag:");
        console.log("   npm run import:users");
      }
    } else {
      console.log(`\n⚠️  ${failed.length} user(s) failed to import. Please check the errors above.`);
    }

    // Show next steps
    if (!isDryRun && failed.length === 0) {
      console.log("\n📚 Next Steps:");
      console.log("   1. Users can now log in using Google OAuth");
      console.log("   2. Admin users can access the admin dashboard");
      console.log("   3. Security users can access security features");
      console.log("   4. Check the user management page to verify roles");
    }

  } catch (error) {
    console.error("❌ Error during users import:", error.message);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log("\n🔌 Database connection closed");
    process.exit(0);
  }
};

// Show help if requested
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
🔧 VNR Keys User Import Script

Usage:
  npm run import:users                 Import users (makes actual changes)
  npm run import:users -- --dry-run    Preview changes without making them
  npm run import:users -- -d           Short form for dry run
  npm run import:users -- --help       Show this help message

Features:
  ✅ Validates user data before import
  ✅ Handles duplicate users gracefully
  ✅ Supports dry-run mode for testing
  ✅ Provides detailed logging and error handling
  ✅ Generates system Google IDs for non-OAuth users

Current Users to Import:
  📧 23071a7228@vnrvjiet.in → admin role
  📧 security@vnrvjiet.in → security role

For more information, check the script documentation.
`);
  process.exit(0);
}

// Run the import function
importUsers();
