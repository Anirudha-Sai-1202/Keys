/**
 * Notification System Test File
 * 
 * This file contains comprehensive tests for the notification system
 * including key reminders, security alerts, and manual testing functions.
 * 
 * Run this file to test the notification functionality without requiring
 * camera/QR scanning capabilities.
 */

import mongoose from 'mongoose';
import User from '../models/user.model.js';
import Key from '../models/key.model.js';
import { Notification } from '../models/notification.model.js';
import {
  createAndSendNotification,
  createKeyReminderNotification,
  createSecurityAlertNotification,
  checkAndSendKeyReminders,
  getUserNotifications,
  markNotificationAsRead,
  getUnreadNotificationCount
} from '../services/notificationService.js';
import { triggerKeyReminderJob } from '../services/scheduledJobs.js';

/**
 * Test Configuration
 */
const TEST_CONFIG = {
  // Test user data
  testFaculty: {
    email: 'test.faculty.notification@vnr.ac.in',
    name: 'Test Faculty Notification',
    role: 'faculty',
    department: 'CSE',
    facultyId: 'TESTFAC' + Date.now(),
    googleId: 'test_faculty_notification_' + Date.now()
  },
  testSecurity: {
    email: 'test.security.notification@vnr.ac.in',
    name: 'Test Security Notification',
    role: 'security',
    googleId: 'test_security_notification_' + Date.now()
  },
  // Test key data
  testKeys: [
    {
      keyNumber: 'TESTNOTIF001',
      keyName: 'Test Notification Lab 1',
      location: 'Block A, Floor 1',
      status: 'unavailable'
    },
    {
      keyNumber: 'TESTNOTIF002',
      keyName: 'Test Notification Lab 2',
      location: 'Block A, Floor 2',
      status: 'unavailable'
    }
  ]
};

/**
 * Setup test data
 */
const setupTestData = async () => {
  console.log('🧪 Setting up test data...');
  
  try {
    // Clean up existing test data
    await User.deleteMany({ email: { $regex: /test\..*notification/i } });
    await Key.deleteMany({ keyNumber: { $regex: /^TESTNOTIF/i } });
    await Notification.deleteMany({ 'metadata.isTest': true });
    
    // Create test faculty user
    const facultyUser = new User(TEST_CONFIG.testFaculty);
    await facultyUser.save();
    console.log('✅ Test faculty user created:', facultyUser.email);
    
    // Create test security user
    const securityUser = new User(TEST_CONFIG.testSecurity);
    await securityUser.save();
    console.log('✅ Test security user created:', securityUser.email);
    
    // Create test keys and assign them to faculty
    const testKeys = [];
    for (const keyData of TEST_CONFIG.testKeys) {
      const key = new Key({
        ...keyData,
        takenBy: {
          userId: facultyUser._id,
          name: facultyUser.name,
          email: facultyUser.email
        },
        takenAt: new Date(Date.now() - 8 * 60 * 60 * 1000) // 8 hours ago
      });
      await key.save();
      testKeys.push(key);
      console.log('✅ Test key created:', key.keyNumber);
    }
    
    return {
      facultyUser,
      securityUser,
      testKeys
    };
  } catch (error) {
    console.error('❌ Error setting up test data:', error);
    throw error;
  }
};

/**
 * Test basic notification creation
 */
const testBasicNotification = async (user) => {
  console.log('\n🧪 Testing basic notification creation...');
  
  try {
    const notificationData = {
      recipient: {
        userId: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      type: 'system_alert',
      title: 'Test Notification',
      message: 'This is a test notification to verify the system is working correctly.',
      priority: 'medium',
      metadata: {
        isTest: true,
        testType: 'basic'
      }
    };
    
    const notification = await createAndSendNotification(notificationData);
    console.log('✅ Basic notification created:', notification._id);
    
    return notification;
  } catch (error) {
    console.error('❌ Error testing basic notification:', error);
    throw error;
  }
};

/**
 * Test key reminder notification
 */
const testKeyReminderNotification = async (facultyUser, testKeys) => {
  console.log('\n🧪 Testing key reminder notification...');
  
  try {
    const notification = await createKeyReminderNotification(facultyUser, testKeys);
    console.log('✅ Key reminder notification created:', notification._id);
    console.log('📧 Notification details:');
    console.log('   Title:', notification.title);
    console.log('   Message:', notification.message);
    console.log('   Priority:', notification.priority);
    
    return notification;
  } catch (error) {
    console.error('❌ Error testing key reminder notification:', error);
    throw error;
  }
};

/**
 * Test security alert notification
 */
const testSecurityAlertNotification = async (facultyUser, testKeys) => {
  console.log('\n🧪 Testing security alert notification...');
  
  try {
    const notifications = await createSecurityAlertNotification(facultyUser, testKeys);
    console.log(`✅ Security alert notifications created: ${notifications.length}`);
    
    for (const notification of notifications) {
      console.log('📧 Security notification details:');
      console.log('   Recipient:', notification.recipient.name);
      console.log('   Title:', notification.title);
      console.log('   Message:', notification.message);
      console.log('   Priority:', notification.priority);
    }
    
    return notifications;
  } catch (error) {
    console.error('❌ Error testing security alert notification:', error);
    throw error;
  }
};

/**
 * Test the complete 5PM reminder flow
 */
const testCompleteReminderFlow = async () => {
  console.log('\n🧪 Testing complete 5PM reminder flow...');
  
  try {
    const result = await checkAndSendKeyReminders();
    console.log('✅ Complete reminder flow executed:');
    console.log('   Faculty notifications:', result.facultyNotifications);
    console.log('   Security notifications:', result.securityNotifications);
    console.log('   Total unreturned keys:', result.totalUnreturnedKeys);
    
    return result;
  } catch (error) {
    console.error('❌ Error testing complete reminder flow:', error);
    throw error;
  }
};

/**
 * Test notification retrieval and management
 */
const testNotificationManagement = async (user) => {
  console.log('\n🧪 Testing notification management...');
  
  try {
    // Get user notifications
    const notifications = await getUserNotifications(user._id);
    console.log(`✅ Retrieved ${notifications.length} notifications for user`);
    
    // Get unread count
    const unreadCount = await getUnreadNotificationCount(user._id);
    console.log(`✅ Unread notification count: ${unreadCount}`);
    
    // Mark first notification as read (if exists)
    if (notifications.length > 0) {
      const firstNotification = notifications[0];
      await markNotificationAsRead(firstNotification._id, user._id);
      console.log('✅ Marked first notification as read');
      
      // Check unread count again
      const newUnreadCount = await getUnreadNotificationCount(user._id);
      console.log(`✅ New unread count: ${newUnreadCount}`);
    }
    
    return { notifications, unreadCount };
  } catch (error) {
    console.error('❌ Error testing notification management:', error);
    throw error;
  }
};

/**
 * Test scheduled job trigger
 */
const testScheduledJobTrigger = async () => {
  console.log('\n🧪 Testing scheduled job trigger...');
  
  try {
    const result = await triggerKeyReminderJob();
    console.log('✅ Scheduled job triggered successfully:', result);
    
    return result;
  } catch (error) {
    console.error('❌ Error testing scheduled job trigger:', error);
    throw error;
  }
};

/**
 * Clean up test data
 */
const cleanupTestData = async () => {
  console.log('\n🧹 Cleaning up test data...');
  
  try {
    // Delete test users
    const deletedUsers = await User.deleteMany({ email: { $regex: /test\..*notification/i } });
    console.log(`✅ Deleted ${deletedUsers.deletedCount} test users`);

    // Delete test keys
    const deletedKeys = await Key.deleteMany({ keyNumber: { $regex: /^TESTNOTIF/i } });
    console.log(`✅ Deleted ${deletedKeys.deletedCount} test keys`);
    
    // Delete test notifications
    const deletedNotifications = await Notification.deleteMany({ 'metadata.isTest': true });
    console.log(`✅ Deleted ${deletedNotifications.deletedCount} test notifications`);
    
    console.log('✅ Test data cleanup completed');
  } catch (error) {
    console.error('❌ Error cleaning up test data:', error);
    throw error;
  }
};

/**
 * Run all tests
 */
const runAllTests = async () => {
  console.log('🚀 Starting comprehensive notification system tests...\n');
  
  try {
    // Setup test data
    const { facultyUser, securityUser, testKeys } = await setupTestData();
    
    // Test basic notification
    await testBasicNotification(facultyUser);
    
    // Test key reminder notification
    await testKeyReminderNotification(facultyUser, testKeys);
    
    // Test security alert notification
    await testSecurityAlertNotification(facultyUser, testKeys);
    
    // Test complete reminder flow
    await testCompleteReminderFlow();
    
    // Test notification management
    await testNotificationManagement(facultyUser);
    await testNotificationManagement(securityUser);
    
    // Test scheduled job trigger
    await testScheduledJobTrigger();
    
    console.log('\n✅ All tests completed successfully!');
    console.log('\n📊 Test Summary:');
    console.log('   ✅ Basic notification creation');
    console.log('   ✅ Key reminder notifications');
    console.log('   ✅ Security alert notifications');
    console.log('   ✅ Complete 5PM reminder flow');
    console.log('   ✅ Notification management');
    console.log('   ✅ Scheduled job trigger');
    
    // Cleanup
    await cleanupTestData();
    
  } catch (error) {
    console.error('\n❌ Test failed:', error);
    
    // Attempt cleanup even if tests failed
    try {
      await cleanupTestData();
    } catch (cleanupError) {
      console.error('❌ Cleanup also failed:', cleanupError);
    }
    
    throw error;
  }
};

// Export individual test functions for selective testing
export {
  TEST_CONFIG,
  setupTestData,
  testBasicNotification,
  testKeyReminderNotification,
  testSecurityAlertNotification,
  testCompleteReminderFlow,
  testNotificationManagement,
  testScheduledJobTrigger,
  cleanupTestData,
  runAllTests
};

// If this file is run directly, execute all tests
if (import.meta.url === `file://${process.argv[1]}`) {
  // Connect to database first
  import('../config/env.js');
  import('../db/connectDB.js').then(({ connectDB }) => {
    connectDB().then(() => {
      console.log('📡 Connected to database for testing');
      runAllTests().then(() => {
        console.log('\n🎉 All notification tests completed successfully!');
        process.exit(0);
      }).catch((error) => {
        console.error('\n💥 Tests failed:', error);
        process.exit(1);
      });
    }).catch((error) => {
      console.error('❌ Failed to connect to database:', error);
      process.exit(1);
    });
  });
}
