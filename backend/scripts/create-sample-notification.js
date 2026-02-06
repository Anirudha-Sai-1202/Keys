import mongoose from 'mongoose';
import { MONGO_URI } from '../config/env.js';
import User from '../models/user.model.js';
import { Notification } from '../models/notification.model.js';

// Connect to MongoDB
await mongoose.connect(MONGO_URI);
console.log('Connected to MongoDB');

try {
  // Find a faculty user with unreturned keys
  const facultyUser = await User.findOne({ role: 'faculty' });

  if (!facultyUser) {
    console.log('No faculty user found. Please create a faculty user first.');
    process.exit(1);
  }

  // Find an unreturned key for testing
  const { Key } = await import('../models/key.model.js');
  const unreturnedKey = await Key.findOne({
    status: 'unavailable',
    'takenBy.userId': facultyUser._id
  });

  if (!unreturnedKey) {
    console.log('No unreturned keys found for faculty. Creating a sample key reminder notification anyway.');

    // Create a sample key reminder notification
    const notification = new Notification({
      recipient: {
        userId: facultyUser._id,
        name: facultyUser.name,
        email: facultyUser.email,
        role: facultyUser.role,
      },  
      title: 'Key Return Reminder - 1 Key Pending',
      message: `You have 1 unreturned key: Sample Key (Sample Location). Please return it as soon as possible.`,
      type: 'key_reminder',
      priority: 'high',
      read: false,
      isActive: true,
      metadata: {
        keyCount: 1,
        reminderType: 'sample'
      }
    });

    await notification.save();
    console.log('✅ Sample key reminder notification created successfully');
    console.log('Notification:', {
      id: notification._id,
      title: notification.title,
      message: notification.message,
      recipient: notification.recipient.name
    });
  } else {
    console.log(`Found unreturned key: ${unreturnedKey.keyNumber} (${unreturnedKey.keyName})`);

    // Create a realistic key reminder notification
    const notification = new Notification({
      recipient: {
        userId: facultyUser._id,
        name: facultyUser.name,
        email: facultyUser.email,
        role: facultyUser.role,
      },
      title: 'Key Return Reminder - 1 Key Pending',
      message: `You have 1 unreturned key: ${unreturnedKey.keyNumber} (${unreturnedKey.keyName}). Please return it as soon as possible.`,
      type: 'key_reminder',
      priority: 'high',
      read: false,
      isActive: true,
      metadata: {
        keyCount: 1,
        keyIds: [unreturnedKey._id],
        reminderType: 'sample'
      }
    });

    await notification.save();
    console.log('✅ Key reminder notification created successfully');
    console.log('Notification:', {
      id: notification._id,
      title: notification.title,
      message: notification.message,
      recipient: notification.recipient.name,
      keyInfo: `${unreturnedKey.keyNumber} (${unreturnedKey.keyName})`
    });
  }

} catch (error) {
  console.error('❌ Error creating notification:', error);
} finally {
  await mongoose.disconnect();
  console.log('Disconnected from MongoDB');
}
