// src/pages/dashboard/NotificationsSlidebar.jsx
import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bell, CheckCircle, AlertTriangle, Info, X } from "lucide-react";

function NotificationsSlidebar({ isOpen, onClose }) {
  const notifications = [
    {
      id: 1,
      type: "success",
      title: "User verified",
      message: "John Doe has been verified successfully.",
      time: "2 mins ago",
    },
    {
      id: 2,
      type: "alert",
      title: "Unusual login attempt",
      message: "Suspicious activity detected from new device.",
      time: "10 mins ago",
    },
    {
      id: 3,
      type: "info",
      title: "New registration",
      message: "Jane Smith just signed up.",
      time: "30 mins ago",
    },
    {
      id: 4,
      type: "success",
      title: "Database backup complete",
      message: "System backup completed successfully.",
      time: "1 hour ago",
    },
  ];

  const getIcon = (type) => {
    switch (type) {
      case "success":
        return <CheckCircle className="text-green-400" size={20} />;
      case "alert":
        return <AlertTriangle className="text-red-400" size={20} />;
      case "info":
        return <Info className="text-blue-400" size={20} />;
      default:
        return <Bell className="text-gray-400" size={20} />;
    }
  };

  // Parent animation (stagger children)
  const listVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.12, // delay between each notification
      },
    },
  };

  // Each notification animation
  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.4, ease: "easeOut" },
    },
  };

  // When notifications open/close, notify other components (sidebar)
  useEffect(() => {
    const OPEN = "vnr:notifications:open";
    const CLOSED = "vnr:notifications:closed";
    if (isOpen) {
      window.dispatchEvent(new CustomEvent(OPEN));
    } else {
      window.dispatchEvent(new CustomEvent(CLOSED));
    }
  }, [isOpen]);

  // Close notifications if sidebar opens elsewhere
  useEffect(() => {
    const onSidebarOpen = () => {
      if (isOpen && typeof onClose === "function") onClose();
    };
    window.addEventListener("vnr:sidebar:open", onSidebarOpen);
    return () => window.removeEventListener("vnr:sidebar:open", onSidebarOpen);
  }, [isOpen, onClose]);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Overlay */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.5 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black z-40"
          />

          {/* Slidebar */}
          <motion.div
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{
              type: "tween",
              ease: [0.25, 0.1, 0.25, 1], // buttery smooth easing
              duration: 0.7,
            }}
            className="fixed right-0 top-0 h-full w-80 bg-gray-900 border-l border-gray-700 shadow-lg z-50 flex flex-col"
          >
            {/* Header */}
<div className="flex items-center justify-between p-4 border-b border-blue-500">
              <h2 className="text-white font-semibold text-lg">
                Notifications
              </h2>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Notifications list with staggered animation */}
            <motion.div
              variants={listVariants}
              initial="hidden"
              animate="show"
              exit="hidden"
              className="flex-1 overflow-y-auto p-4 space-y-4"
            >
              {notifications.map((n) => (
                <motion.div
                  key={n.id}
                  variants={itemVariants}
                  className="flex items-start space-x-3 p-3 bg-gray-800/50 border border-gray-700 rounded-2xl hover:shadow-[0_0_12px_rgba(59,130,246,0.5)] transition-all duration-200"
                >
                  {/* Icon */}
                  <div className="mt-1">{getIcon(n.type)}</div>

                  {/* Content */}
                  <div className="flex-1">
                    <h3 className="text-white font-medium text-sm">{n.title}</h3>
                    <p className="text-gray-400 text-xs">{n.message}</p>
                    <span className="text-gray-500 text-xs">{n.time}</span>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

export default NotificationsSlidebar;
