import { motion } from "framer-motion";
import { useAuthStore } from "../../store/authStore";
import { formatDate } from "../../utils/date";
import { User, Calendar, Camera } from "lucide-react";
import { useSidebar } from "../../components/layout/DashboardLayout";

const ProfilePage = () => {
  const { user } = useAuthStore();
  const { sidebarOpen } = useSidebar();

  return (
    <div
      className={`space-y-6 ${sidebarOpen ? "p-4 lg:p-6" : "p-4 lg:p-8 xl:px-12"}`}
      style={{
        background:
          "radial-gradient(circle at 50% 30%, #1e293b 0%, #0f172a 100%)",
      }}
    >
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center"
      >
        <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 text-transparent bg-clip-text mb-2">
          Profile Settings
        </h1>
        <p className="text-gray-300">
          Manage your account information and preferences
        </p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Card */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-1"
        >
          <div className="bg-gray-900/60 backdrop-blur-xl rounded-2xl p-6 border border-gray-700">
            <div className="text-center">
              {/* Profile Picture */}
              <div className="relative inline-block mb-4">
                <div className="w-24 h-24 bg-gradient-to-tr from-blue-500 to-cyan-400 rounded-full flex items-center justify-center text-white text-2xl font-bold drop-shadow-[0_0_15px_rgba(59,130,246,0.6)]">
                  {user?.name?.charAt(0)?.toUpperCase() || "U"}
                </div>
                <button className="absolute bottom-0 right-0 p-2 bg-gray-800 rounded-full border-2 border-gray-700 hover:bg-gray-700 transition-colors duration-200">
                  <Camera size={16} className="text-gray-300" />
                </button>
              </div>

              <h2 className="text-xl font-bold text-white mb-1">{user?.name}</h2>
              <p className="text-gray-400 mb-1">{user?.email}</p>
              {user?.role === "faculty" && (
                <>
                  <p className="text-blue-400 font-medium mb-1">
                    {user?.department}
                  </p>
                  <p className="text-gray-500 text-sm mb-4">
                    Faculty ID: {user?.facultyId}
                  </p>
                </>
              )}
              {user?.role !== "faculty" && <div className="mb-4"></div>}

              {/* Account Info */}
              <div className="space-y-3 text-left">
                <div className="flex items-center space-x-3 p-3 bg-gray-800/50 rounded-lg ">
                  <Calendar size={16} className="text-blue-400" />
                  <div>
                    <p className="text-gray-400 text-xs">Member since</p>
                    <p className="text-white text-sm">
                      {new Date(user?.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-3 p-3 bg-gray-800/50 rounded-lg ">
                  <User size={16} className="text-blue-400" />
                  <div>
                    <p className="text-gray-400 text-xs">Last login</p>
                    <p className="text-white text-sm">{formatDate(user?.lastLogin)}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Profile Info (Read-only) */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-2"
        >
          <div className="bg-gray-900/60 backdrop-blur-xl rounded-2xl p-6 border border-gray-700">
            <h2 className="text-xl font-bold text-white mb-6">Personal Information</h2>
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <p className="text-sm font-medium text-gray-300 mb-1">Full Name</p>
                  <p className="text-white bg-gray-800/50 p-3 rounded-lg border border-gray-700">{user?.name}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-300 mb-1">Email Address</p>
                  <p className="text-white bg-gray-800/50 p-3 rounded-lg border border-gray-700">{user?.email}</p>
                </div>
              </div>

              {user?.role === "faculty" && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <p className="text-sm font-medium text-gray-300 mb-1">Department</p>
                    <p className="text-white bg-gray-800/50 p-3 rounded-lg border border-gray-700">
                      {user?.department}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-300 mb-1">Faculty ID</p>
                    <p className="text-white bg-gray-800/50 p-3 rounded-lg border border-gray-700">
                      {user?.facultyId}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default ProfilePage;
