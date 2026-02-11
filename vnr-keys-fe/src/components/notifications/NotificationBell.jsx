import { useState, useEffect } from 'react';
import { Bell } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import NotificationSlidePanel from './NotificationSlidePanel';
import { useNotificationStore } from '../../store/notificationStore';

const NotificationBell = () => {
  const [isOpen, setIsOpen] = useState(false);
  const {
    unreadCount,
    fetchNotifications,
    initializeSocket,
    disconnectSocket
  } = useNotificationStore();

  useEffect(() => {
    // Fetch notifications on component mount
    fetchNotifications();
    
    // Initialize socket connection for real-time notifications
    initializeSocket();

    // Set up polling for new notifications every 30 seconds (backup)
    const interval = setInterval(() => {
      fetchNotifications();
    }, 30000);

    return () => {
      clearInterval(interval);
      disconnectSocket();
    };
  }, [fetchNotifications, initializeSocket, disconnectSocket]);

  const handleBellClick = () => {
    setIsOpen(true);
  };

  return (
    <>
      {/* Notification Bell Button */}
      <motion.button
        onClick={handleBellClick}
        className="relative p-2 text-gray-400 hover:text-white transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800 rounded-lg"
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
      >
        <Bell className="h-6 w-6" />

        {/* Unread Count Badge */}
        <AnimatePresence>
          {unreadCount > 0 && (
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0, opacity: 0 }}
              className="absolute -top-1 -right-1 bg-red-500 text-white text-xs font-bold rounded-full h-5 w-5 flex items-center justify-center min-w-[20px]"
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Pulse Animation for New Notifications */}
        {unreadCount > 0 && (
          <motion.div
            className="absolute -top-1 -right-1 bg-red-500 rounded-full h-5 w-5"
            animate={{
              scale: [1, 1.2, 1],
              opacity: [0.7, 0.3, 0.7],
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        )}
      </motion.button>

      {/* Notification Slide Panel */}
      <NotificationSlidePanel
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
      />
    </>
  );
};

export default NotificationBell;
