import mongoose from 'mongoose';
import { MONGO_URI } from '../config/env.js';
import User from '../models/user.model.js';
import { createAndSendNotification } from '../services/notificationService.js';

// Connect to MongoDB
await mongoose.connect(MONGO_URI);
console.log('Connected to MongoDB');

try {
  // Find a faculty user
  const facultyUser = await User.findOne({ role: 'faculty' });

  if (!facultyUser) {
    console.log('No faculty user found. Please create a faculty user first.');
    process.exit(1);
  }

  console.log(`Found faculty user: ${facultyUser.name} (${facultyUser.email})`);

  // Create a test notification
  const notificationData = {
    recipient: {
      userId: facultyUser._id,
      name: facultyUser.name,
      email: facultyUser.email,
      role: facultyUser.role,
    },
    title: 'Test Notification',
    message: 'This is a test notification to verify the notification system is working properly.',
    type: 'system',
    priority: 'medium',
    metadata: {
      testType: 'system_test',
      timestamp: new Date().toISOString()
    }
  };

  // Create and send the notification
  const notification = await createAndSendNotification(notificationData, {
    email: false,  // Don't send email for test
    realTime: true // Send real-time notification
  });

  console.log('✅ Test notification created successfully');
  console.log('Notification details:', {
    id: notification._id,
    title: notification.title,
    message: notification.message,
    type: notification.type,
    priority: notification.priority,
    recipient: notification.recipient.name,
    createdAt: notification.createdAt
  });

  // Also create a security alert notification for testing
  const securityUsers = await User.find({ role: 'security' });
  
  if (securityUsers.length > 0) {
    const securityUser = securityUsers[0];
    
    const securityNotificationData = {
      recipient: {
        userId: securityUser._id,
        name: securityUser.name,
        email: securityUser.email,
        role: securityUser.role,
      },
      title: 'Security Test Alert',
      message: 'This is a test security alert notification.',
      type: 'security_alert',
      priority: 'high',
      metadata: {
        testType: 'security_test',
        timestamp: new Date().toISOString()
      }
    };

    const securityNotification = await createAndSendNotification(securityNotificationData, {
      email: false,
      realTime: true
    });

    console.log('✅ Security test notification created successfully');
    console.log('Security notification details:', {
      id: securityNotification._id,
      title: securityNotification.title,
      recipient: securityNotification.recipient.name
    });
  }

} catch (error) {
  console.error('❌ Error testing notification system:', error);
} finally {
  await mongoose.disconnect();
  console.log('Disconnected from MongoDB');
}
