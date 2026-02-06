/* eslint-disable react-refresh/only-export-components */
import { useState, createContext, useContext } from "react";
import { Outlet } from "react-router-dom";
import { motion } from "framer-motion";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";

// Create context for sidebar state
const SidebarContext = createContext();

// Custom hook to use sidebar context
export const useSidebar = () => {
  const context = useContext(SidebarContext);
  if (!context) {
    throw new Error('useSidebar must be used within a SidebarContext.Provider');
  }
  return context;
};

const DashboardLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 relative overflow-hidden">
      {/* Removed Floating Shapes and green gradient for a dark theme */}
      <Navbar sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} />

      <div className="flex h-[calc(100vh-4rem)] relative z-10">
        {/* Sidebar */}
        <Sidebar sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} />

        {/* Main content */}
        <motion.main
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
          className="flex-1 overflow-auto"
        >
          <SidebarContext.Provider value={{ sidebarOpen }}>
            <Outlet />
          </SidebarContext.Provider>
        </motion.main>
      </div>
    </div>
  );
};

export default DashboardLayout;
