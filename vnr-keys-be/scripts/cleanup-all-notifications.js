import mongoose from 'mongoose';
import { MONGO_URI } from '../config/env.js';
import { Notification } from '../models/notification.model.js';

// Connect to MongoDB
await mongoose.connect(MONGO_URI);
console.log('Connected to MongoDB');

try {
  // Delete all notifications
  const result = await Notification.deleteMany({});
  console.log(`✅ Deleted ${result.deletedCount} notifications`);

  // Show remaining notifications count
  const remainingCount = await Notification.countDocuments();
  console.log(`📊 Remaining notifications: ${remainingCount}`);

} catch (error) {
  console.error('❌ Error cleaning up notifications:', error);
} finally {
  await mongoose.disconnect();
  console.log('Disconnected from MongoDB');
}
