// src/components/layout/Navbar.jsx
import { motion } from "framer-motion";
import { Menu, X, User, LogOut } from "lucide-react";
import { useAuthStore } from "../../store/authStore";
import NotificationBell from "../notifications/NotificationBell";
import { useState, useEffect, useRef } from 'react';

const Navbar = ({ sidebarOpen, setSidebarOpen }) => {
  const { user, logout } = useAuthStore();
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  const handleLogout = () => {
    logout();
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [dropdownRef]);

  return (
    <>
      {/* Navbar */}
      <motion.nav
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        className="bg-gray-900 bg-opacity-95 backdrop-filter backdrop-blur-lg border-b border-gray-800 px-4 py-3 sticky top-0 z-50"
      >
        <div className="flex items-center justify-between">
          {/* Left side - Menu button and Logo */}
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-800 transition-colors duration-200"
            >
              {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
            </button>

            <div className="flex items-center space-x-2">
              {/* Logo */}
              <div className="w-10 h-10 flex items-center justify-center rounded-lg bg-white shadow-md">
                <img
                  src="/logo.png"
                  alt="logo"
                  style={{
                    width: "70%",
                    height: "70%",
                    objectFit: "contain",
                  }}
                />
              </div>
              <h1 className="text-xl font-bold text-white">
                Vnr Keys
              </h1>
            </div>
          </div>

          {/* Right side - User menu */}
          <div className="flex items-center space-x-4">
            {/* Notifications */}
            <NotificationBell />

            {/* User dropdown */}
            <div className="relative" ref={dropdownRef}>
              <button onClick={() => setIsDropdownOpen(!isDropdownOpen)} className="flex items-center space-x-2 p-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-800 transition-colors duration-200">
                <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                  <User size={16} className="text-white" />
                </div>
                <span className="hidden md:block text-sm font-medium">
                  {user?.name}
                </span>
              </button>

              {/* Dropdown menu */}
              <div className={`absolute right-0 mt-2 w-48 bg-gray-800 rounded-lg shadow-lg border border-gray-700 transition-all duration-200 z-50 ${isDropdownOpen ? 'opacity-100 visible' : 'opacity-0 invisible'}`}>
                <div className="p-3 border-b border-gray-700">
                  <p className="text-sm font-medium text-white">{user?.name}</p>
                  <p className="text-xs text-gray-400">{user?.email}</p>
                </div>
                <div className="p-2">
                  <button
                    onClick={handleLogout}
                    className="flex items-center space-x-2 w-full p-2 text-left text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors duration-200"
                  >
                    <LogOut size={16} />
                    <span className="text-sm">Logout</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </motion.nav>

      {/* 🔔 Notifications Sidebar */}
    </>
  );
};

export default Navbar;
