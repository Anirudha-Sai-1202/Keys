import { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Bell,
  CheckCircle,
  AlertTriangle,
  Info,
  RefreshCw
} from 'lucide-react';
import { useNotificationStore } from '../../store/notificationStore';
import { formatDistanceToNow } from 'date-fns';
import { useNavigate } from 'react-router-dom'; // Changed from Navigate to useNavigate

const NotificationSlidePanel = ({ isOpen, onClose }) => {
  const {
    notifications,
    loading,
    error,
    fetchNotifications,
    markAsRead
  } = useNotificationStore();
  const navigate = useNavigate(); // Changed from Navigate() to useNavigate()
  
  useEffect(() => {
    if (isOpen) {
      fetchNotifications();
    }
  }, [isOpen, fetchNotifications]);

  const handleNotificationClicks = () => {
    navigate('/dashboard/notifications');
    onClose(); // Optional: close the panel after navigation
  }
  
  const getNotificationIcon = (title) => {
    // Key-specific icon logic
    if (title.toLowerCase().includes('reminder')) {
      return <AlertTriangle className="h-5 w-5 text-orange-400" />;
    }
    if (title.toLowerCase().includes('returned')) {
      return <CheckCircle className="h-5 w-5 text-green-400" />;
    }
    if (title.toLowerCase().includes('unreturned') || title.toLowerCase().includes('alert')) {
      return <AlertTriangle className="h-5 w-5 text-red-400" />;
    }
    // Default for any key-related notification
    return <Info className="h-5 w-5 text-blue-400" />;
  };

  const handleNotificationClick = (notification) => {
    if (!notification.read) {
      markAsRead(notification._id);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-50 z-40"
            onClick={onClose}
          />

          {/* Slide Panel */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed right-0 top-0 h-screen w-full max-w-md bg-slate-900 shadow-2xl z-50 flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-slate-700">
              <h2 className="text-xl font-semibold text-white">Notifications</h2>
              <button
                onClick={onClose}
                className="p-2 text-gray-400 hover:text-white transition-colors"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            {/* Error Message */}
            {error && (
              <div className="p-4 bg-red-900/20 border-b border-red-500/30">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <span className="text-red-300 text-sm">{error}</span>
                </div>
              </div>
            )}

            {/* Notifications List */}
            <div className="flex-1 overflow-y-auto min-h-0">
              <AnimatePresence>
                {loading ? (
                  <div className="h-full flex items-center justify-center">
                    <div className="text-center">
                      <RefreshCw className="h-6 w-6 animate-spin text-blue-400 mx-auto mb-2" />
                      <p className="text-gray-400 text-sm">Loading notifications...</p>
                    </div>
                  </div>
                ) : notifications.length === 0 ? (
                  <div className="h-full flex items-center justify-center">
                    <div className="text-center">
                      <Bell className="h-16 w-16 text-gray-600 mx-auto mb-4" />
                      <h3 className="text-xl font-medium text-gray-300 mb-2">No notifications</h3>
                      <p className="text-gray-400">You're all caught up!</p>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 space-y-3 pb-6">
                    {/* Show only last 5 notifications */}
                    {notifications.slice(0, 5).map((notification, index) => (
                      <motion.div
                        key={notification._id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.05 }}
                        className={`p-4 rounded-xl border cursor-pointer transition-all duration-200 ${
                          notification.read
                            ? 'bg-slate-800/50 border-slate-700 hover:bg-slate-800'
                            : 'bg-slate-800 border-slate-600 hover:bg-slate-700'
                        }`}
                        onClick={() => handleNotificationClick(notification)}
                      >
                        <div className="flex items-start gap-3">
                          {/* Icon */}
                          <div className="flex-shrink-0 mt-0.5">
                            {getNotificationIcon(notification.title)}
                          </div>

                          {/* Content */}
                          <div className="flex-1 min-w-0">
                            <h4 className={`font-medium mb-1 ${
                              notification.read ? 'text-gray-300' : 'text-white'
                            }`}>
                              {notification.title}
                            </h4>

                            <p className={`text-sm mb-2 ${
                              notification.read ? 'text-gray-400' : 'text-gray-300'
                            }`}>
                              {notification.message}
                            </p>

                            <div className="text-xs text-gray-500">
                              {formatDistanceToNow(new Date(notification.createdAt), { addSuffix: true })}
                            </div>
                          </div>

                          {/* Unread Indicator */}
                          {!notification.read && (
                            <div className="w-2 h-2 bg-blue-500 rounded-full flex-shrink-0 mt-2"></div>
                          )}
                        </div>
                      </motion.div>
                    ))}

                    {/* See More button - only show if there are more than 5 notifications */}
                    {notifications.length > 5 && (
                      <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="pt-2"
                      >
                        <button 
                          onClick={handleNotificationClicks}
                          className="w-full py-2 px-4 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
                        >
                          See More ({notifications.length - 5} more)
                        </button>
                      </motion.div>
                    )}
                  </div>
                )}
              </AnimatePresence>
            </div>

          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default NotificationSlidePanel;