import { motion } from "framer-motion";
import { Building2 } from "lucide-react";

const DepartmentCard = ({ department, keyCount, onClick, isSelected = false }) => {
  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={`
        bg-gray-800 border border-gray-700 rounded-2xl p-5 cursor-pointer
        transition-all duration-500
        hover:shadow-[0_0_20px_rgba(99,102,241,0.5)] hover:border-indigo-500
        ${isSelected ? "ring-2 ring-indigo-500 shadow-lg bg-gray-700" : ""}
      `}
    >
      {/* Header with icon + key count */}
      <div className="flex items-center justify-between mb-3">
        <Building2
          className={`w-6 h-6 transition-colors duration-300 ${
            isSelected ? "text-indigo-400" : "text-gray-400"
          }`}
        />
        <span
          className={`text-sm font-medium px-2 py-1 rounded-full border flex items-center gap-1 transition-colors duration-300
            ${
              isSelected
                ? "bg-indigo-500/20 text-indigo-300 border-indigo-400/40"
                : "bg-gray-700/40 text-gray-300 border-gray-600/40"
            }`}
        >
          {keyCount} keys
        </span>
      </div>

      {/* Department name */}
      <h3
        className={`text-lg font-bold mb-2 transition-colors duration-300 ${
          isSelected ? "text-indigo-300" : "text-white"
        }`}
      >
        {department}
      </h3>

      {/* Bottom row */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-gray-400">Department</span>
        <div
          className={`w-2 h-2 rounded-full transition-colors duration-300 ${
            isSelected ? "bg-indigo-400" : "bg-gray-500"
          }`}
        ></div>
      </div>
    </motion.div>
  );
};

export default DepartmentCard;
