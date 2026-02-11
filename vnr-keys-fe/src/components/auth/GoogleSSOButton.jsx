import { useState } from "react";
import { motion } from "framer-motion";
import { GoogleOAuthProvider, GoogleLogin } from "@react-oauth/google";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import toast from "react-hot-toast";
import { config } from "../../utils/config.js";

const GoogleSSOButton = () => {
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();
    const { loginWithSSO, getRoleBasedRoute } = useAuthStore();

    const handleSuccess = async (credentialResponse) => {
        setIsLoading(true);
        try {
            console.log("🔐 Google SSO Success - exchanging token...");

            // Extract the Google ID token
            const googleToken = credentialResponse.credential;

            // Send to SSO server via backend
            await loginWithSSO(googleToken);

            toast.success("Successfully logged in with SSO!");

            // Get route and do full page reload to ensure cookies are loaded
            const route = getRoleBasedRoute();
            window.location.href = route;
        } catch (error) {
            console.error("SSO login error:", error);
            toast.error(error.message || "SSO login failed");
            setIsLoading(false);
        }
    };

    const handleError = () => {
        console.error("Google SSO Login Failed");
        toast.error("Google login failed. Please try again.");
    };

    return (
        <GoogleOAuthProvider clientId={import.meta.env.VITE_GOOGLE_CLIENT_ID}>
            <div className="w-full">
                {isLoading ? (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="w-full flex items-center justify-center gap-3 px-4 py-3 border border-blue-300 rounded-lg bg-blue-50"
                    >
                        <div className="w-5 h-5 border-2 border-blue-300 border-t-blue-600 rounded-full animate-spin"></div>
                        <span className="text-blue-700 font-medium">Logging in with SSO...</span>
                    </motion.div>
                ) : (
                    <GoogleLogin
                        onSuccess={handleSuccess}
                        onError={handleError}
                        useOneTap={false}
                        theme="outline"
                        size="large"
                        text="continue_with"
                        width="100%"
                        logo_alignment="left"
                    />
                )}
            </div>
        </GoogleOAuthProvider>
    );
};

export default GoogleSSOButton;
