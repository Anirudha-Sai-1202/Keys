import mongoose from 'mongoose';
import { MONGO_URI } from '../config/env.js';
import { Notification } from '../models/notification.model.js';

// Connect to MongoDB
await mongoose.connect(MONGO_URI);
console.log('Connected to MongoDB');

try {
  // Find expired notifications
  const expiredNotifications = await Notification.find({
    expiresAt: { $lt: new Date() }
  });

  console.log(`Found ${expiredNotifications.length} expired notifications`);

  if (expiredNotifications.length > 0) {
    // Delete expired notifications
    const result = await Notification.deleteMany({
      expiresAt: { $lt: new Date() }
    });

    console.log(`✅ Deleted ${result.deletedCount} expired notifications`);
  } else {
    console.log('✅ No expired notifications to delete');
  }

  // Show remaining notifications count
  const remainingCount = await Notification.countDocuments();
  console.log(`📊 Remaining notifications: ${remainingCount}`);

} catch (error) {
  console.error('❌ Error cleaning up notifications:', error);
} finally {
  await mongoose.disconnect();
  console.log('Disconnected from MongoDB');
}
