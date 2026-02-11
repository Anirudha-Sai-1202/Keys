import mongoose from 'mongoose';
import { MONGO_URI } from '../config/env.js';
import { checkAndSendKeyReminders } from '../services/notificationService.js';

// Connect to MongoDB
await mongoose.connect(MONGO_URI);
console.log('Connected to MongoDB');

try {
  console.log('🔔 Testing 5 PM key reminder job...');
  
  const result = await checkAndSendKeyReminders();
  
  console.log('✅ 5 PM reminder job test completed:');
  console.log(`   📧 Faculty notifications sent: ${result.facultyNotifications}`);
  console.log(`   🔒 Security notifications sent: ${result.securityNotifications}`);

  if (result.facultyNotifications === 0 && result.securityNotifications === 0) {
    console.log('ℹ️  No unreturned keys found, so no notifications were sent.');
    console.log('   This is normal if all keys are currently returned.');
  }

} catch (error) {
  console.error('❌ Error testing 5 PM reminders:', error);
} finally {
  await mongoose.disconnect();
  console.log('Disconnected from MongoDB');
}
