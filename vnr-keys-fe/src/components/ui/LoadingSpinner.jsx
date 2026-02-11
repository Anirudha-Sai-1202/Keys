import { motion } from "framer-motion";
import { FaKey } from "react-icons/fa";

const LoadingSpinner = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-700 flex items-center justify-center overflow-hidden">
      {/* Dark Gradient Loading Spinner Centered */}
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
        style={{ display: "inline-block" }}
      >
        <FaKey size={64} color="#3B82F6" /> {/* Tailwind blue-500 */}
      </motion.div>
    </div>
  );
};

export default LoadingSpinner;
