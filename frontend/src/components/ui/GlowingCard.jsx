import { motion } from "framer-motion";

export const GlowingCard = ({ children, className = "" }) => {
  return (
    <motion.div
      whileHover={{ scale: 1.03, boxShadow: "0 0 20px rgba(59, 130, 246, 0.6)" }}
      className={`bg-gray-800 rounded-2xl shadow-md border border-gray-700 transition-all duration-300 ${className}`}
    >
      {children}
    </motion.div>
  );
};

