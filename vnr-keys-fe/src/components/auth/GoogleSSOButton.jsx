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
            console.log("🔐 Google SSO Success - logging in...");

            // Extract the Google ID token
            const googleToken = credentialResponse.credential;

            // Call loginWithSSO which handles everything
            await loginWithSSO(googleToken);

            // Show success message
            toast.success("Successfully logged in!");

            // Navigate using React Router (NO page reload)
            const route = getRoleBasedRoute();
            navigate(route, { replace: true });
        } catch (error) {
            console.error("SSO login error:", error);
            // Error message is already set in authStore and loginWithSSO throws it
            toast.error(error.message || "Authentication failed");
            setIsLoading(false);
        }
    };

    const handleError = () => {
        console.error("Google SSO Login Failed");
        toast.error("Google login failed. Please try again.");
    };

    return (
        <GoogleOAuthProvider clientId={import.meta.env.VITE_GOOGLE_CLIENT_ID}>
            <div className="w-full flex flex-col items-center gap-4">
                {/* Google SSO Button Container with Google's styles */}
                <div style={{ position: 'relative', justifyItems: 'center', width: '100%' }}>
                    <GoogleLogin
                        onSuccess={handleSuccess}
                        onError={handleError}
                        text="continue_with"
                        theme="outline"
                        size="large"
                        width="100%"
                        logo_alignment="left"
                        useOneTap={false}
                        disabled={isLoading}
                    />
                </div>

                {isLoading && (
                    <div className="flex items-center gap-2 text-gray-400">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500"></div>
                        <span className="text-sm">Authenticating...</span>
                    </div>
                )}
            </div>
        </GoogleOAuthProvider>
    );
};

export default GoogleSSOButton;
