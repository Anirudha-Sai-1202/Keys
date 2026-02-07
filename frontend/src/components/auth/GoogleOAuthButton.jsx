
import { useEffect, useRef } from "react";

const GoogleOAuthButton = ({ isLoading = false, disabled = false }) => {
  const buttonRef = useRef(null);

  useEffect(() => {
    const renderButton = () => {
      if (!window.google?.accounts?.id || !buttonRef.current) return false;
      window.google.accounts.id.renderButton(buttonRef.current, {
        type: "standard",
        theme: "outline",
        size: "large",
        width: buttonRef.current.offsetWidth || 320,
        text: "continue_with",
        shape: "rectangular",
        logo_alignment: "left"
      });
      return true;
    };

    if (renderButton()) return;

    const onReady = () => renderButton();
    window.addEventListener("gis:ready", onReady);

    return () => {
      window.removeEventListener("gis:ready", onReady);
    };
  }, []);

  return (
    <div
      className={`w-full ${disabled || isLoading ? "opacity-60 pointer-events-none" : ""}`}
    >
      <div ref={buttonRef} className="w-full flex justify-center" />
    </div>
  );
};

export default GoogleOAuthButton;
