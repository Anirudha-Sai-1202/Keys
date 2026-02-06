import { motion } from "framer-motion";

const BottomNavigation = ({ tabs, activeTab, onTabChange }) => {
  return (
    <div className="fixed bottom-0 left-0 right-0 bg-white/10 backdrop-blur-md border-t border-white/20 z-40">
      <div className="flex items-center justify-center gap-6 py-2 px-4 max-w-md mx-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`flex flex-col items-center justify-center p-3 rounded-xl transition-all duration-200 min-w-0 flex-1 ${
              activeTab === tab.id
                ? "bg-white/20 text-white"
                : "text-gray-400 hover:text-white hover:bg-white/10"
            }`}
          >
            <div className="relative">
              {tab.icon}
              {typeof tab.badge === 'number' && (
                <span className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                  {tab.badge}
                </span>
              )}
            </div>
            <span className="text-xs font-medium mt-1 truncate max-w-full">
              {tab.label}
            </span>
            {activeTab === tab.id && (
              <motion.div
                layoutId="activeTab"
                className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-white rounded-full"
              />
            )}
          </button>
        ))}
      </div>
    </div>
  );
};

export default BottomNavigation;
