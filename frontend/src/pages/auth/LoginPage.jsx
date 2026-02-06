import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { useSearchParams, useNavigate } from "react-router-dom";
import GoogleOAuthButton from "../../components/auth/GoogleOAuthButton";
import { useAuthStore } from "../../store/authStore";
import toast from "react-hot-toast";

const LoginPage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const hasShownToast = useRef(false);

  const { isLoading, error, checkAuth, getRoleBasedRoute } = useAuthStore();

  // Extract search params
  const authStatus = searchParams.get("auth");
  const errorParam = searchParams.get("error");

  // Handle OAuth callback
  useEffect(() => {
    // Prevent showing toast multiple times
    if (hasShownToast.current) return;

    if (authStatus === "success") {
      hasShownToast.current = true;
      toast.success("Successfully logged in with Google!");
      checkAuth().then(() => {
        const route = getRoleBasedRoute();
        navigate(route, { replace: true });
      });
    } else if (errorParam) {
      hasShownToast.current = true;
      // Handle different error types
      const errorMessages = {
        invalid_domain: "❌ Email is not valid. Please use your @vnrvjiet.in email address. Contact admin if you need access.",
        user_not_registered: "❌ Email is not registered in the system. Please contact the admin to get access.",
        google_mismatch: "⚠️ Your Google account is linked to a different account. Contact admin for support.",
        auth_failed: "❌ Authentication failed. Please try again."
      };
      
      const errorMessage = errorMessages[errorParam] || errorMessages.auth_failed;
      toast.error(errorMessage);
      console.error("Auth error:", errorParam);
      
      // Clean up URL after showing error
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, [authStatus, errorParam, checkAuth, getRoleBasedRoute, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden px-4 bg-gradient-to-br from-blue-950 via-slate-900 to-black">
      
      {/* 🔵 Animated glowing background blobs */}
      <div className="absolute inset-0 -z-10">
        <motion.div
          className="absolute w-[700px] h-[700px] bg-blue-500/10 rounded-full blur-3xl"
          animate={{ x: [0, 40, 0], y: [0, 30, 0] }}
          transition={{ repeat: Infinity, duration: 15, ease: "easeInOut" }}
          style={{ top: "-200px", left: "-150px" }}
        />
        <motion.div
          className="absolute w-[500px] h-[500px] bg-cyan-400/10 rounded-full blur-3xl"
          animate={{ x: [0, -30, 0], y: [0, -40, 0] }}
          transition={{ repeat: Infinity, duration: 18, ease: "easeInOut" }}
          style={{ bottom: "-150px", right: "-150px" }}
        />
      </div>

      {/* 🔐 Keycard-styled login card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="max-w-md w-full bg-slate-900/70 backdrop-blur-xl rounded-2xl 
          border border-blue-500/30 p-6
          transition-all duration-500 
          hover:shadow-[0_0_25px_rgba(59,130,246,0.6)] hover:border-blue-400"
      >
        {/* Title */}
        <h2 className="text-2xl font-bold mb-4 text-center bg-gradient-to-r from-blue-400 to-cyan-500 text-transparent bg-clip-text">
          Welcome to VNR Keys
        </h2>

        <p className="text-gray-300 text-center mb-5">
          Sign in with your Google account to continue
        </p>

        {error && (
          <p className="text-red-500 font-semibold mb-3 text-center">{error}</p>
        )}

        {/* Google OAuth Button */}
        <GoogleOAuthButton isLoading={isLoading} />

        {/* Inline footer (no box) */}
        <p className="text-sm text-gray-400 text-center mt-4">
          Secure access with Google authentication
        </p>
      </motion.div>
    </div>
  );
};

export default LoginPage;
